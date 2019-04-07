module.exports = createAuthDirective;

const { parse } = require('esprima');
const { defaultFieldResolver } = require('graphql');
const { SchemaDirectiveVisitor } = require('graphql-tools');
const { AuthenticationError } = require('apollo-server-core');

function createAuthDirective({ directiveName = 'auth', userField = 'user' } = {}) {
    class AuthDirective extends SchemaDirectiveVisitor {
        visitObject(object) {
            Object.keys(object._fields).forEach(field => this.visitFieldDefinition(object._fields[field]));
        }
        visitFieldDefinition(field) {
            const originalResolver = field.resolve || defaultFieldResolver;
            const checks = this.args.checks && this.args.checks.map(prepareCheck);
            // Note: We attach the handler so it can be overwritten in the case an object
            //  scope directive was set
            field.usageValidation = usageValidation;
            field.resolve = resolve;

            function prepareCheck(check) {
                // Create a function to access the property
                check.fieldValue = buildAccessorFunction(check.field);
                return check;
            }

            async function resolve(root, args, context, info) {
                if (typeof field.usageValidation === 'function') {
                    field.usageValidation();
                }
                const result = await originalResolver(root, args, context, info);
                return result;
            }

            function usageValidation() {
                if (userField && !context[userField]) {
                    throw new AuthenticationError('User not authenticated');
                }
                if (Array.isArray(checks)) {
                    checks.forEach(filter => validate(field.name, context, filter));
                }
            }

            function validate(fieldName, context, filter) {
                switch (filter.op) {
                    case 'LT': {
                        const value = filter.fieldValue(context);
                        if (value < filter.value === false){
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `less than ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'LTE': {
                        const value = filter.fieldValue(context);
                        if (value <= filter.value === false) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `less than or equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'EQ': {
                        const value = filter.fieldValue(context);
                        if (value != filter.value) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'NE': {
                        const value = filter.fieldValue(context);
                        if (value == filter.value) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is ` +
                                `equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'GTE': {
                        const value = filter.fieldValue(context);
                        if (value >= filter.value === false) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `greater than or equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'GT': {
                        const value = filter.fieldValue(context);
                        if (value >= filter.value === false) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `greater than ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'CONTAINS':
                    case 'NOT_CONTAINS': {
                        const value = filter.fieldValue(context);
                        const contains = Array.isArray(value) ?
                            value.includes(filter.field.value) :
                            value === filter.value;
                        if (filter.op === 'CONTAINS' && !contains) {
                            console.info(`User invalid because context.${filter.field} (${JSON.stringify(value)}) does ` +
                                `not contain ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        } else if (filter.op === 'NOT_CONTAINS' && contains) {
                            console.info(`User invalid because context.${filter.field} (${JSON.stringify(value)}) ` +
                                `contains ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    default:
                        throw new Error(`Invalid operation enumeration value "${filter.op}" received!`);
                }
            }
        }
    }
    // TODO: Add OBJECT
    const AuthDirectiveSchema = `
        enum AuthDirectiveOperation {
            LT
            LTE
            EQ
            NE
            GTE
            GT
            CONTAINS
            NOT_CONTAINS
        }

        input AuthDirectiveInput {
            field: String!
            op: AuthDirectiveOperation!
            value: String!
        }

        directive @${directiveName}(
            checks: [AuthDirectiveInput!]
        ) on OBJECT | FIELD_DEFINITION
    `;
    return { AuthDirective, AuthDirectiveSchema };

    function buildAccessorFunction(str) {
        const names = getNames();
        return function accessor(context) {
            let obj = context;
            const nameValues = names.slice();
            while (obj != undefined && nameValues.length) {
                obj = obj[nameValues.shift()];
            }
            return obj;
        };

        function getNames() {
            let ast = parse(str);
            if (!ast || !ast.body || !ast.body[0] || ast.body[0].type !== 'ExpressionStatement') {
                throw new Error(`Unable to parse "${str}"`);
            }
            ast = ast.body[0].expression;

            const parts = Array.from(process(ast));
            return parts;

            function* process(node) {
                if (node.type === 'Identifier') {
                    yield node.name;
                } else if (node.type === 'MemberExpression') {
                    for (const identifier of process(node.object)) {
                        yield identifier;
                    }
                    if (node.property.type === 'Literal') {
                        yield node.property.value;
                    } else if (node.property.type === 'Identifier') {
                        yield node.property.name;
                    } else {
                        throw new Error(`Unable to parse "${str}"`);
                    }
                } else if (node.type === 'ArrayExpression') {
                    if (node.elements.length === 1 || node.elements[0].type !== 'Literal') {
                        yield node.elements[0].value;
                    } else {
                        throw new Error(`Unable to parse "${str}"`);
                    }
                } else {
                    throw new Error(`Invalid AST node type "${node.type}" received`);
                }
            }
        }
    }
}
