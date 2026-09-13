/**
 * The fixed list of well-known API-documentation/introspection paths the opt-in probe checks.
 * Sourced from pentest-book.com's common API paths list. Extend this list, don't invent new
 * probe types -- see plan doc's "Opt-in doc-path probe" section.
 */
export const WELL_KNOWN_API_DOC_PATHS: string[] = [
  "/swagger.json",
  "/swagger.yaml",
  "/swagger/v1/swagger.json",
  "/openapi.json",
  "/openapi.yaml",
  "/v2/api-docs",
  "/v3/api-docs",
  "/api-docs",
  "/api-docs.json",
  "/.well-known/openapi.json",
  "/graphiql",
  "/graphql/schema.json",
  "/actuator",
  "/actuator/health",
  "/actuator/env",
  "/.well-known/schema-discovery",
];
