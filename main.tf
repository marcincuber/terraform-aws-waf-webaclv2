#####
# WAFv2 web acl
#####
resource "aws_wafv2_web_acl" "main" {
  count = var.enabled ? 1 : 0

  name  = var.name_prefix
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = var.rules
    content {
      name     = lookup(rule.value, "name")
      priority = lookup(rule.value, "priority")

      override_action {
        none {}
      }

      statement {
        dynamic "managed_rule_group_statement" {
          for_each = length(lookup(rule.value, "managed_rule_group_statement", {})) == 0 ? [] : [lookup(rule.value, "managed_rule_group_statement", {})]
          content {
            name        = lookup(managed_rule_group_statement.value, "name")
            vendor_name = lookup(managed_rule_group_statement.value, "vendor_name", "AWS")

            dynamic "excluded_rule" {
              for_each = length(lookup(managed_rule_group_statement.value, "excluded_rule", {})) == 0 ? [] : toset(lookup(managed_rule_group_statement.value, "excluded_rule"))
              content {
                name = excluded_rule.value
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = length(lookup(rule.value, "visibility_config")) == 0 ? [] : [lookup(rule.value, "visibility_config", {})]
        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = lookup(visibility_config.value, "metric_name", "${var.name_prefix}-default-rule-metric-name")
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  tags = var.tags

  dynamic "visibility_config" {
    for_each = length(var.visibility_config) == 0 ? [] : [var.visibility_config]
    content {
      cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
      metric_name                = lookup(visibility_config.value, "metric_name", "${var.name_prefix}-default-web-acl-metric-name")
      sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
    }
  }
}

#####
# WAFv2 web acl association with ALB
#####
resource "aws_wafv2_web_acl_association" "main" {
  count = var.enabled && var.create_alb_association ? 1 : 0

  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn

  depends_on = [aws_wafv2_web_acl.main]
}

#####
# WAFv2 web acl logging configuration with kinesis firehose
#####
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.enabled && var.create_logging_configuration ? 1 : 0

  log_destination_configs = var.log_destination_configs #["${aws_kinesis_firehose_delivery_stream.example.arn}"]
  resource_arn            = aws_wafv2_web_acl.main[0].arn

  dynamic "redacted_fields" {
    for_each = var.redacted_fields
    content {
      dynamic "single_header" {
        for_each = length(lookup(redacted_fields.value, "single_header", {})) == 0 ? [] : [lookup(redacted_fields.value, "single_header", {})]
        content {
          name = lookup(single_header.value, "name", null)
        }
      }

      dynamic "single_query_argument" {
        for_each = length(lookup(redacted_fields.value, "single_query_argument", {})) == 0 ? [] : [lookup(redacted_fields.value, "single_query_argument", {})]
        content {
          name = lookup(single_query_argument.value, "name", null)
        }
      }
    }
  }
}
