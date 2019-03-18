module.exports = createAuthDirective;

const { defaultFieldResolver } = require('graphql');
const { SchemaDirectiveVisitor } = require('graphql-tools');
const { AuthenticationError } = require('apollo-server-core');

function createAuthDirective({ userField = 'user' } = {}) {
    class AuthDirective extends SchemaDirectiveVisitor {
        visitFieldDefinition(field) {
            const originalResolver = field.resolve || defaultFieldResolver;
            const checks = this.args.checks
                .map(prepareCheck);
            field.resolve = resolve;

            function prepareCheck(check) {
                const fieldStr = fullFieldName(check.field);
                // Create a field getter
                check.fieldValue = new Function('context', `return ${fieldStr};`);
                return check;

                function fullFieldName(accessor) {
                    if (accessor.trim().startsWith('[')) {
                        return `context${accessor}`;
                    } else {
                        return `context.${accessor}`;
                    }
                }
            }

            async function resolve(root, args, context, info) {
                if (userField && !context[userField]) {
                    throw new AuthenticationError('User not authenticated');
                }
                if (Array.isArray(checks)) {
                    checks.forEach(filter => validate(field.name, context, filter));
                }
                const result = await originalResolver(root, args, context, info);
                return result;
            }

            function validate(fieldName, context, filter) {
                switch (filter.op) {
                    case 'LT':
                    case 'LESS_THAN': {
                        const value = filter.fieldValue(context);
                        if (value < filter.value === false){
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `less than ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'LTE':
                    case 'LESS_THAN_EQUAL': {
                        const value = filter.fieldValue(context);
                        if (value <= filter.value === false) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `less than or equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'E':
                    case 'EQ':
                    case 'EQUAL': {
                        const value = filter.fieldValue(context);
                        if (value != filter.value) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'NE':
                    case 'NEQ':
                    case 'NOT_EQUAL': {
                        const value = filter.fieldValue(context);
                        if (value == filter.value) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is ` +
                                `equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'GTE':
                    case 'GREATER_THAN_EQUAL': {
                        const value = filter.fieldValue(context);
                        if (value >= filter.value === false) {
                            console.info(`User invalid because context.${filter.field} ("${value}") is not ` +
                                `greater than or equal to ${filter.value}`);
                            throw new AuthenticationError(`User not allowed to access "${fieldName}"`);
                        }
                        break;
                    }
                    case 'GT':
                    case 'GREATER_THAN': {
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

    const AuthDirectiveSchema = `
        enum AuthDirectiveOperation {
            LT
            LTE
            E
            EQ
            NE
            NEQ
            GTE
            GT
            LESS_THAN
            LESS_THAN_EQUAL
            EQUAL
            NOT_EQUAL
            GREATER_THAN_EQUAL
            GREATER_THAN
            CONTAINS
            NOT_CONTAINS
        }

        input AuthDirectiveInput {
            field: String!
            op: AuthDirectiveOperation!
            value: String!
        }

        directive @auth(
            checks: [AuthDirectiveInput!]
        ) on FIELD_DEFINITION
    `;
    return { AuthDirective, AuthDirectiveSchema };
}
