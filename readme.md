# Graphql Context Authorization Directive
This directive (default `@auth`) checks if the user exists on the context (field name default to `"user"` pass false to disable check). And the processes the `checks` parameter to check every field defined and it's appropriate operation.

## Usage

    const { ApolloServer } = require('apollo-server');
    const createAuthDirective = require('@major-mann/graphql-directive-context-auth');
    const { AuthDirective, AuthDirectiveSchema } = createAuthDirective({
        userField = 'user',
        directiveName = 'auth'
    });

    const server = new ApolloServer({
        typeDefs: [
            AuthDirectiveSchema,
            `
                type Query {
                    # Will only allow foo to be resolved if context.token.sub == '123' (Note the use of double equal instead of triple)
                    foo: String @auth(checks: [{ field: 'token.sub', op: 'EQ', value: '123' }])
                }
            `
        ],
        schemaDirectives: {
            auth: AuthDirective
        }
    });


