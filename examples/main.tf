terraform {
  required_providers {
    wafrule = {
      version = ">= 0.0.1"
    }
  }
  required_version = ">= 0.13"
}

provider "wafrule" {
  region = "eu-west-1"
  # also support credentials options like aws provider
}


resource "wafrule_acl_rule" "test" {
  waf_acl_name = "FMManagedWebACLV2test1613985747206"   # WAF ACL name available in AWS Console
  waf_acl_id   = "fbcf121f-8bcd-4361-ad7c-8277e1f1d178" # WAF ID available in AWS Console

  # rule synatax is the same as for https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#rules
  rule {

    name     = "rule-1"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "SizeRestrictions_QUERYSTRING"
        }

        excluded_rule {
          name = "NoUserAgent_HEADER"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }

  }

}
