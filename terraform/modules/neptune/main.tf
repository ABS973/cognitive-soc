# ─── Behavioral Baselines Table ──────────────────────────────────
# Stores per-entity behavioral fingerprints across 8 dimensions
resource "aws_dynamodb_table" "baselines" {
  name         = "cognitive-soc-baselines-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "entity_id"

  attribute {
    name = "entity_id"
    type = "S"
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption  { enabled = true }

  tags = { Name = "cognitive-soc-baselines-${var.environment}" }
}

# ─── Identity Graph Table ────────────────────────────────────────
# Adjacency list representing the Living Identity Graph
resource "aws_dynamodb_table" "graph" {
  name         = "cognitive-soc-graph-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "edge_id"

  attribute {
    name = "edge_id"
    type = "S"
  }

  # GSI for querying by from_node (get all edges from an entity)
  global_secondary_index {
    name            = "from-node-index"
    hash_key        = "from_node"
    projection_type = "ALL"
  }

  attribute {
    name = "from_node"
    type = "S"
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption  { enabled = true }

  tags = { Name = "cognitive-soc-graph-${var.environment}" }
}

# ─── Anomaly Scores History Table ────────────────────────────────
resource "aws_dynamodb_table" "anomaly_scores" {
  name         = "cognitive-soc-anomaly-scores-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "entity_id"
  range_key    = "timestamp"

  attribute {
    name = "entity_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption  { enabled = true }

  tags = { Name = "cognitive-soc-anomaly-scores-${var.environment}" }
}

output "baselines_table_name"     { value = aws_dynamodb_table.baselines.name }
output "graph_table_name"         { value = aws_dynamodb_table.graph.name }
output "anomaly_scores_table_name"{ value = aws_dynamodb_table.anomaly_scores.name }

variable "environment" { type = string }
