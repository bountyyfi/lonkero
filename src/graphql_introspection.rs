// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! GraphQL Introspection and Schema Parsing
//! Performs full introspection queries and parses schemas for targeted scanning

use crate::http_client::HttpClient;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Full introspection query - discovers entire schema
const FULL_INTROSPECTION_QUERY: &str = r#"{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
        defaultValue
      }
      interfaces { name }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          kind
          name
          ofType { kind name ofType { kind name } }
        }
        defaultValue
      }
    }
  }
}"#;

/// Parsed GraphQL schema from introspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLSchema {
    /// GraphQL endpoint URL
    pub endpoint: String,
    /// Query type name (usually "Query")
    pub query_type: Option<String>,
    /// Mutation type name (usually "Mutation")
    pub mutation_type: Option<String>,
    /// Subscription type name (usually "Subscription")
    pub subscription_type: Option<String>,
    /// All types discovered
    pub types: Vec<GraphQLType>,
    /// All directives
    pub directives: Vec<GraphQLDirective>,
    /// Parsed queries (fields on Query type)
    pub queries: Vec<GraphQLOperation>,
    /// Parsed mutations (fields on Mutation type)
    pub mutations: Vec<GraphQLOperation>,
    /// Parsed subscriptions (fields on Subscription type)
    pub subscriptions: Vec<GraphQLOperation>,
    /// Custom scalars discovered
    pub custom_scalars: Vec<String>,
    /// Enums discovered
    pub enums: HashMap<String, Vec<String>>,
    /// Whether introspection was successful
    pub introspection_enabled: bool,
}

/// GraphQL type from schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLType {
    pub kind: String,
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<GraphQLField>,
    pub input_fields: Vec<GraphQLInputField>,
    pub enum_values: Vec<String>,
    pub interfaces: Vec<String>,
    pub possible_types: Vec<String>,
}

/// GraphQL field on a type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLField {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<GraphQLArgument>,
    pub type_name: String,
    pub type_kind: String,
    pub is_list: bool,
    pub is_non_null: bool,
    pub is_deprecated: bool,
    pub deprecation_reason: Option<String>,
}

/// GraphQL input field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLInputField {
    pub name: String,
    pub description: Option<String>,
    pub type_name: String,
    pub type_kind: String,
    pub is_list: bool,
    pub is_non_null: bool,
    pub default_value: Option<String>,
}

/// GraphQL argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLArgument {
    pub name: String,
    pub description: Option<String>,
    pub type_name: String,
    pub type_kind: String,
    pub is_list: bool,
    pub is_non_null: bool,
    pub default_value: Option<String>,
}

/// GraphQL operation (query, mutation, or subscription)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLOperation {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<GraphQLArgument>,
    pub return_type: String,
    pub return_kind: String,
    pub is_list: bool,
    pub is_deprecated: bool,
    /// Whether this operation likely requires authentication (heuristic)
    pub likely_requires_auth: bool,
    /// Whether this operation handles sensitive data (heuristic)
    pub handles_sensitive_data: bool,
}

/// GraphQL directive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLDirective {
    pub name: String,
    pub description: Option<String>,
    pub locations: Vec<String>,
    pub args: Vec<GraphQLArgument>,
}

/// GraphQL introspection client
pub struct GraphQLIntrospector {
    http_client: Arc<HttpClient>,
}

impl GraphQLIntrospector {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Perform full introspection on a GraphQL endpoint
    pub async fn introspect(&self, endpoint: &str) -> Result<GraphQLSchema> {
        info!("[GraphQL] Running full introspection on: {}", endpoint);

        // Try POST first (most common)
        let query_body = serde_json::json!({
            "query": FULL_INTROSPECTION_QUERY
        });

        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let response = self
            .http_client
            .post_with_headers(endpoint, &query_body.to_string(), headers.clone())
            .await
            .context("Failed to send introspection query")?;

        // Check if introspection is disabled
        if response.body.contains("introspection")
            && (response.body.contains("disabled") || response.body.contains("not allowed"))
        {
            info!("[GraphQL] Introspection is disabled on {}", endpoint);
            return Ok(GraphQLSchema {
                endpoint: endpoint.to_string(),
                query_type: None,
                mutation_type: None,
                subscription_type: None,
                types: Vec::new(),
                directives: Vec::new(),
                queries: Vec::new(),
                mutations: Vec::new(),
                subscriptions: Vec::new(),
                custom_scalars: Vec::new(),
                enums: HashMap::new(),
                introspection_enabled: false,
            });
        }

        // Parse the response
        self.parse_introspection_response(endpoint, &response.body)
    }

    /// Try multiple common GraphQL paths and return first successful introspection
    pub async fn discover_and_introspect(&self, base_url: &str) -> Result<Vec<GraphQLSchema>> {
        let base = base_url.trim_end_matches('/');
        let paths = vec![
            "",
            "/graphql",
            "/api/graphql",
            "/query",
            "/gql",
            "/api/gql",
            "/v1/graphql",
            "/v2/graphql",
        ];

        let mut schemas = Vec::new();

        for path in paths {
            let endpoint = if path.is_empty() {
                base.to_string()
            } else {
                format!("{}{}", base, path)
            };

            match self.introspect(&endpoint).await {
                Ok(schema) if schema.introspection_enabled => {
                    info!(
                        "[GraphQL] Successfully introspected {}: {} queries, {} mutations, {} subscriptions",
                        endpoint,
                        schema.queries.len(),
                        schema.mutations.len(),
                        schema.subscriptions.len()
                    );
                    schemas.push(schema);
                }
                Ok(_) => {
                    debug!("[GraphQL] Introspection disabled on {}", endpoint);
                }
                Err(e) => {
                    debug!("[GraphQL] Failed to introspect {}: {}", endpoint, e);
                }
            }
        }

        Ok(schemas)
    }

    /// Parse introspection response into structured schema
    fn parse_introspection_response(&self, endpoint: &str, body: &str) -> Result<GraphQLSchema> {
        let json: serde_json::Value =
            serde_json::from_str(body).context("Failed to parse introspection response as JSON")?;

        let schema_data = json
            .get("data")
            .and_then(|d| d.get("__schema"))
            .context("No __schema in introspection response")?;

        // Extract root type names
        let query_type = schema_data
            .get("queryType")
            .and_then(|qt| qt.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        let mutation_type = schema_data
            .get("mutationType")
            .and_then(|mt| mt.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        let subscription_type = schema_data
            .get("subscriptionType")
            .and_then(|st| st.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        // Parse all types
        let mut types = Vec::new();
        let mut custom_scalars = Vec::new();
        let mut enums: HashMap<String, Vec<String>> = HashMap::new();
        let mut type_map: HashMap<String, GraphQLType> = HashMap::new();

        if let Some(types_array) = schema_data.get("types").and_then(|t| t.as_array()) {
            for type_def in types_array {
                if let Some(parsed_type) = self.parse_type(type_def) {
                    // Skip internal types
                    if parsed_type.name.starts_with("__") {
                        continue;
                    }

                    // Track custom scalars
                    if parsed_type.kind == "SCALAR" && !is_builtin_scalar(&parsed_type.name) {
                        custom_scalars.push(parsed_type.name.clone());
                    }

                    // Track enums
                    if parsed_type.kind == "ENUM" {
                        enums.insert(parsed_type.name.clone(), parsed_type.enum_values.clone());
                    }

                    type_map.insert(parsed_type.name.clone(), parsed_type.clone());
                    types.push(parsed_type);
                }
            }
        }

        // Parse directives
        let mut directives = Vec::new();
        if let Some(dir_array) = schema_data.get("directives").and_then(|d| d.as_array()) {
            for dir_def in dir_array {
                if let Some(directive) = self.parse_directive(dir_def) {
                    directives.push(directive);
                }
            }
        }

        // Extract operations from root types
        let queries = query_type
            .as_ref()
            .and_then(|qt| type_map.get(qt))
            .map(|t| self.extract_operations(&t.fields))
            .unwrap_or_default();

        let mutations = mutation_type
            .as_ref()
            .and_then(|mt| type_map.get(mt))
            .map(|t| self.extract_operations(&t.fields))
            .unwrap_or_default();

        let subscriptions = subscription_type
            .as_ref()
            .and_then(|st| type_map.get(st))
            .map(|t| self.extract_operations(&t.fields))
            .unwrap_or_default();

        info!(
            "[GraphQL] Parsed schema: {} types, {} queries, {} mutations, {} subscriptions, {} custom scalars",
            types.len(),
            queries.len(),
            mutations.len(),
            subscriptions.len(),
            custom_scalars.len()
        );

        Ok(GraphQLSchema {
            endpoint: endpoint.to_string(),
            query_type,
            mutation_type,
            subscription_type,
            types,
            directives,
            queries,
            mutations,
            subscriptions,
            custom_scalars,
            enums,
            introspection_enabled: true,
        })
    }

    /// Parse a single type definition
    fn parse_type(&self, type_def: &serde_json::Value) -> Option<GraphQLType> {
        let kind = type_def.get("kind")?.as_str()?.to_string();
        let name = type_def.get("name")?.as_str()?.to_string();
        let description = type_def
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        // Parse fields
        let fields = type_def
            .get("fields")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| self.parse_field(f))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Parse input fields
        let input_fields = type_def
            .get("inputFields")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| self.parse_input_field(f))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Parse enum values
        let enum_values = type_def
            .get("enumValues")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Parse interfaces
        let interfaces = type_def
            .get("interfaces")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Parse possible types
        let possible_types = type_def
            .get("possibleTypes")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(GraphQLType {
            kind,
            name,
            description,
            fields,
            input_fields,
            enum_values,
            interfaces,
            possible_types,
        })
    }

    /// Parse a field definition
    fn parse_field(&self, field_def: &serde_json::Value) -> Option<GraphQLField> {
        let name = field_def.get("name")?.as_str()?.to_string();
        let description = field_def
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        // Parse type info
        let type_info = field_def.get("type")?;
        let (type_name, type_kind, is_list, is_non_null) = self.parse_type_ref(type_info);

        // Parse args
        let args = field_def
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| self.parse_argument(a))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let is_deprecated = field_def
            .get("isDeprecated")
            .and_then(|d| d.as_bool())
            .unwrap_or(false);

        let deprecation_reason = field_def
            .get("deprecationReason")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string());

        Some(GraphQLField {
            name,
            description,
            args,
            type_name,
            type_kind,
            is_list,
            is_non_null,
            is_deprecated,
            deprecation_reason,
        })
    }

    /// Parse an input field definition
    fn parse_input_field(&self, field_def: &serde_json::Value) -> Option<GraphQLInputField> {
        let name = field_def.get("name")?.as_str()?.to_string();
        let description = field_def
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let type_info = field_def.get("type")?;
        let (type_name, type_kind, is_list, is_non_null) = self.parse_type_ref(type_info);

        let default_value = field_def
            .get("defaultValue")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        Some(GraphQLInputField {
            name,
            description,
            type_name,
            type_kind,
            is_list,
            is_non_null,
            default_value,
        })
    }

    /// Parse an argument definition
    fn parse_argument(&self, arg_def: &serde_json::Value) -> Option<GraphQLArgument> {
        let name = arg_def.get("name")?.as_str()?.to_string();
        let description = arg_def
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let type_info = arg_def.get("type")?;
        let (type_name, type_kind, is_list, is_non_null) = self.parse_type_ref(type_info);

        let default_value = arg_def
            .get("defaultValue")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        Some(GraphQLArgument {
            name,
            description,
            type_name,
            type_kind,
            is_list,
            is_non_null,
            default_value,
        })
    }

    /// Parse a type reference (handles NON_NULL, LIST wrappers)
    fn parse_type_ref(&self, type_ref: &serde_json::Value) -> (String, String, bool, bool) {
        let mut current = type_ref;
        let mut is_list = false;
        let mut is_non_null = false;

        // Unwrap wrappers
        loop {
            let kind = current.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            match kind {
                "NON_NULL" => {
                    is_non_null = true;
                    if let Some(of_type) = current.get("ofType") {
                        current = of_type;
                    } else {
                        break;
                    }
                }
                "LIST" => {
                    is_list = true;
                    if let Some(of_type) = current.get("ofType") {
                        current = of_type;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        let type_name = current
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let type_kind = current
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("SCALAR")
            .to_string();

        (type_name, type_kind, is_list, is_non_null)
    }

    /// Parse a directive definition
    fn parse_directive(&self, dir_def: &serde_json::Value) -> Option<GraphQLDirective> {
        let name = dir_def.get("name")?.as_str()?.to_string();
        let description = dir_def
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let locations = dir_def
            .get("locations")
            .and_then(|l| l.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let args = dir_def
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| self.parse_argument(a))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(GraphQLDirective {
            name,
            description,
            locations,
            args,
        })
    }

    /// Extract operations from fields
    fn extract_operations(&self, fields: &[GraphQLField]) -> Vec<GraphQLOperation> {
        fields
            .iter()
            .map(|field| {
                let likely_requires_auth = self.likely_requires_auth(&field.name, &field.args);
                let handles_sensitive_data =
                    self.handles_sensitive_data(&field.name, &field.return_type, &field.args);

                GraphQLOperation {
                    name: field.name.clone(),
                    description: field.description.clone(),
                    args: field.args.clone(),
                    return_type: field.type_name.clone(),
                    return_kind: field.type_kind.clone(),
                    is_list: field.is_list,
                    is_deprecated: field.is_deprecated,
                    likely_requires_auth,
                    handles_sensitive_data,
                }
            })
            .collect()
    }

    /// Heuristic: does this operation likely require authentication?
    fn likely_requires_auth(&self, name: &str, args: &[GraphQLArgument]) -> bool {
        let auth_keywords = [
            "me",
            "current",
            "my",
            "profile",
            "account",
            "dashboard",
            "admin",
            "private",
            "protected",
            "user",
            "settings",
            "preference",
        ];

        let name_lower = name.to_lowercase();
        if auth_keywords.iter().any(|kw| name_lower.contains(kw)) {
            return true;
        }

        // Check for userId, currentUser, etc. in args
        for arg in args {
            let arg_lower = arg.name.to_lowercase();
            if arg_lower.contains("userid")
                || arg_lower.contains("ownerid")
                || arg_lower.contains("currentuser")
            {
                return true;
            }
        }

        false
    }

    /// Heuristic: does this operation handle sensitive data?
    fn handles_sensitive_data(
        &self,
        name: &str,
        return_type: &str,
        args: &[GraphQLArgument],
    ) -> bool {
        let sensitive_keywords = [
            "password",
            "secret",
            "token",
            "credit",
            "card",
            "ssn",
            "social",
            "bank",
            "account",
            "payment",
            "billing",
            "email",
            "phone",
            "address",
            "dob",
            "birthdate",
            "passport",
            "license",
            "salary",
            "income",
            "tax",
            "medical",
            "health",
        ];

        let name_lower = name.to_lowercase();
        let return_lower = return_type.to_lowercase();

        if sensitive_keywords
            .iter()
            .any(|kw| name_lower.contains(kw) || return_lower.contains(kw))
        {
            return true;
        }

        for arg in args {
            let arg_lower = arg.name.to_lowercase();
            if sensitive_keywords.iter().any(|kw| arg_lower.contains(kw)) {
                return true;
            }
        }

        false
    }

    /// Generate sample query for an operation
    pub fn generate_sample_query(&self, operation: &GraphQLOperation, op_type: &str) -> String {
        let args_str = if operation.args.is_empty() {
            String::new()
        } else {
            let args = operation
                .args
                .iter()
                .map(|arg| {
                    let sample_value = self.generate_sample_value(&arg.type_name, &arg.type_kind);
                    format!("{}: {}", arg.name, sample_value)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("({})", args)
        };

        format!(
            "{} {{ {}{} {{ __typename }} }}",
            op_type, operation.name, args_str
        )
    }

    /// Generate sample value for a type
    fn generate_sample_value(&self, type_name: &str, type_kind: &str) -> String {
        match type_name.to_lowercase().as_str() {
            "string" | "id" => "\"test123\"".to_string(),
            "int" => "1".to_string(),
            "float" => "1.0".to_string(),
            "boolean" => "true".to_string(),
            _ => {
                if type_kind == "ENUM" {
                    // Just use the type name as placeholder
                    format!("\"{}\"", type_name.to_uppercase())
                } else if type_kind == "INPUT_OBJECT" {
                    "{}".to_string()
                } else {
                    "\"test\"".to_string()
                }
            }
        }
    }
}

/// Check if a scalar is a built-in GraphQL scalar
fn is_builtin_scalar(name: &str) -> bool {
    matches!(name, "String" | "Int" | "Float" | "Boolean" | "ID")
}

impl GraphQLSchema {
    /// Get all operations that likely require authentication
    pub fn get_auth_operations(&self) -> Vec<(&str, &GraphQLOperation)> {
        let mut ops = Vec::new();

        for op in &self.queries {
            if op.likely_requires_auth {
                ops.push(("query", op));
            }
        }
        for op in &self.mutations {
            if op.likely_requires_auth {
                ops.push(("mutation", op));
            }
        }
        for op in &self.subscriptions {
            if op.likely_requires_auth {
                ops.push(("subscription", op));
            }
        }

        ops
    }

    /// Get all operations handling sensitive data
    pub fn get_sensitive_operations(&self) -> Vec<(&str, &GraphQLOperation)> {
        let mut ops = Vec::new();

        for op in &self.queries {
            if op.handles_sensitive_data {
                ops.push(("query", op));
            }
        }
        for op in &self.mutations {
            if op.handles_sensitive_data {
                ops.push(("mutation", op));
            }
        }

        ops
    }

    /// Get mutations that modify data (for IDOR/BOLA testing)
    pub fn get_mutation_targets(&self) -> Vec<&GraphQLOperation> {
        self.mutations
            .iter()
            .filter(|m| {
                let name_lower = m.name.to_lowercase();
                // Look for mutations that modify data
                name_lower.starts_with("create")
                    || name_lower.starts_with("update")
                    || name_lower.starts_with("delete")
                    || name_lower.starts_with("remove")
                    || name_lower.starts_with("add")
                    || name_lower.starts_with("set")
                    || name_lower.starts_with("change")
                    // Check for ID arguments (potential IDOR)
                    || m.args.iter().any(|a| {
                        let n = a.name.to_lowercase();
                        n == "id" || n.ends_with("id") || n.ends_with("_id")
                    })
            })
            .collect()
    }

    /// Generate a summary of the schema for logging
    pub fn summary(&self) -> String {
        format!(
            "GraphQL Schema: {} types, {} queries, {} mutations, {} subscriptions ({} auth-required, {} sensitive)",
            self.types.len(),
            self.queries.len(),
            self.mutations.len(),
            self.subscriptions.len(),
            self.get_auth_operations().len(),
            self.get_sensitive_operations().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_builtin_scalar() {
        assert!(is_builtin_scalar("String"));
        assert!(is_builtin_scalar("Int"));
        assert!(is_builtin_scalar("Float"));
        assert!(is_builtin_scalar("Boolean"));
        assert!(is_builtin_scalar("ID"));
        assert!(!is_builtin_scalar("DateTime"));
        assert!(!is_builtin_scalar("JSON"));
    }

    #[test]
    fn test_operation_auth_detection() {
        let op = GraphQLOperation {
            name: "currentUser".to_string(),
            description: None,
            args: Vec::new(),
            return_type: "User".to_string(),
            return_kind: "OBJECT".to_string(),
            is_list: false,
            is_deprecated: false,
            likely_requires_auth: true,
            handles_sensitive_data: false,
        };

        assert!(op.likely_requires_auth);
    }

    #[test]
    fn test_sensitive_data_detection() {
        let op = GraphQLOperation {
            name: "getUserPaymentMethods".to_string(),
            description: None,
            args: Vec::new(),
            return_type: "PaymentMethod".to_string(),
            return_kind: "OBJECT".to_string(),
            is_list: true,
            is_deprecated: false,
            likely_requires_auth: true,
            handles_sensitive_data: true,
        };

        assert!(op.handles_sensitive_data);
    }
}
