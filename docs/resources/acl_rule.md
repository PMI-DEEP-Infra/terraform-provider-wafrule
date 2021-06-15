# Resource: wafrule_acl_rule

Creates a WAFv2 Web ACL rules.

## Example Usage

This example resource is based on `aws_wafv2_rule_group` that could be created by the AWS provider, check the documentation of the `aws_wafv2_rule_group` resource to see examples of the various available statements: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_rule_group


### Managed Rule

```terraform
resource "wafrule_acl_rule" "example" {
  waf_acl_name  = "Your-account-waf-name"
  waf_acl_id = "Your-account-waf-id"

  rule {
    name     = "managed-rule-example"
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
```

### Rate Based

```terraform
resource "wafrule_acl_rule" "example" {
  waf_acl_name  = "Your-account-waf-name"
  waf_acl_id = "Your-account-waf-id"

  rule {
    name     = "rate-based-example"
    priority = 1

    action {
      count {}
    }

    statement {
      rate_based_statement {
        limit              = 10000
        aggregate_key_type = "IP"

        scope_down_statement {
          geo_match_statement {
            country_codes = ["US", "NL"]
          }
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
```

### Rule Group Reference

```terraform
resource "aws_wafv2_rule_group" "example" {
  capacity = 10
  name     = "example-rule-group"
  scope    = "REGIONAL"

  rule {
    name     = "rule-1"
    priority = 1

    action {
      count {}
    }

    statement {
      geo_match_statement {
        country_codes = ["NL"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "rule-to-exclude-a"
    priority = 10

    action {
      allow {}
    }

    statement {
      geo_match_statement {
        country_codes = ["US"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "rule-to-exclude-b"
    priority = 15

    action {
      allow {}
    }

    statement {
      geo_match_statement {
        country_codes = ["GB"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "friendly-metric-name"
    sampled_requests_enabled   = false
  }
}

resource "wafrule_acl_rule" "test" {
  waf_acl_name  = "Your-account-waf-name"
  waf_acl_id = "Your-account-waf-id"

  rule {
    name     = "rule-1"
    priority = 1

    override_action {
      count {}
    }

    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.example.arn

        excluded_rule {
          name = "rule-to-exclude-b"
        }

        excluded_rule {
          name = "rule-to-exclude-a"
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
```

## Argument Reference

The following arguments are supported:

* `waf_acl_name` - (Required) A name of the WebACL, could be found in AWS Console
* `waf_acl_id` - (Required) An ID of WebACL, could be found in AWS Console
* `rule` - (Required) The rule blocks used to identify the web requests that you want to `allow`, `block`, or `count`. See [Rules](#rules) below for details.

### Rules

~> **NOTE:** One of `action` or `override_action` is required when specifying a rule

Each `rule` supports the following arguments:

* `action` - (Optional) The action that AWS WAF should take on a web request when it matches the rule's statement. This is used only for rules whose **statements do not reference a rule group**. See [Action](#action) below for details.
* `name` - (Required) A friendly name of the rule.
* `override_action` - (Optional) The override action to apply to the rules in a rule group. Used only for rule **statements that reference a rule group**, like `rule_group_reference_statement` and `managed_rule_group_statement`. See [Override Action](#override-action) below for details.
* `priority` - (Required) If you define more than one Rule in a WebACL, AWS WAF evaluates each request against the `rules` in order based on the value of `priority`. AWS WAF processes rules with lower priority first.
* `statement` - (Required) The AWS WAF processing statement for the rule, for example `byte_match_statement` or `geo_match_statement`. See [Statement](#statement) below for details.
* `visibility_config` - (Required) Defines and enables Amazon CloudWatch metrics and web request sample collection. See [Visibility Configuration](#visibility-configuration) below for details.

### Action

The `action` block supports the following arguments:

~> **NOTE:** One of `allow`, `block`, or `count`, expressed as an empty configuration block `{}`, is required when specifying an `action`

* `allow` - (Optional) Instructs AWS WAF to allow the web request. Configure as an empty block `{}`.
* `block` - (Optional) Instructs AWS WAF to block the web request. Configure as an empty block `{}`.
* `count` - (Optional) Instructs AWS WAF to count the web request and allow it. Configure as an empty block `{}`.

### Override Action

The `override_action` block supports the following arguments:

~> **NOTE:** One of `count` or `none`, expressed as an empty configuration block `{}`, is required when specifying an `override_action`

* `count` - (Optional) Override the rule action setting to count (i.e. only count matches). Configured as an empty block `{}`.
* `none` - (Optional) Don't override the rule action setting. Configured as an empty block `{}`.

### Statement

The processing guidance for a Rule, used by AWS WAF to determine whether a web request matches the rule. See the [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements-list.html) for more information.

-> **NOTE:** Although the `statement` block is recursive, currently only 3 levels are supported.

The `statement` block supports the following arguments:

* `and_statement` - (Optional) A logical rule statement used to combine other rule statements with AND logic. See [AND Statement](#and-statement) below for details.
* `byte_match_statement` - (Optional) A rule statement that defines a string match search for AWS WAF to apply to web requests. See [Byte Match Statement](#byte-match-statement) below for details.
* `geo_match_statement` - (Optional) A rule statement used to identify web requests based on country of origin. See [GEO Match Statement](#geo-match-statement) below for details.
* `ip_set_reference_statement` - (Optional) A rule statement used to detect web requests coming from particular IP addresses or address ranges. See [IP Set Reference Statement](#ip-set-reference-statement) below for details.
* `managed_rule_group_statement` - (Optional) A rule statement used to run the rules that are defined in a managed rule group.  This statement can not be nested. See [Managed Rule Group Statement](#managed-rule-group-statement) below for details.
* `not_statement` - (Optional) A logical rule statement used to negate the results of another rule statement. See [NOT Statement](#not-statement) below for details.
* `or_statement` - (Optional) A logical rule statement used to combine other rule statements with OR logic. See [OR Statement](#or-statement) below for details.
* `rate_based_statement` - (Optional) A rate-based rule tracks the rate of requests for each originating `IP address`, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any `5-minute` time span. This statement can not be nested. See [Rate Based Statement](#rate-based-statement) below for details.
* `regex_pattern_set_reference_statement` - (Optional) A rule statement used to search web request components for matches with regular expressions. See [Regex Pattern Set Reference Statement](#regex-pattern-set-reference-statement) below for details.
* `rule_group_reference_statement` - (Optional) A rule statement used to run the rules that are defined in an WAFv2 Rule Group. See [Rule Group Reference Statement](#rule-group-reference-statement) below for details.
* `size_constraint_statement` - (Optional) A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<). See [Size Constraint Statement](#size-constraint-statement) below for more details.
* `sqli_match_statement` - (Optional) An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. See [SQL Injection Match Statement](#sql-injection-match-statement) below for details.
* `xss_match_statement` - (Optional) A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests. See [XSS Match Statement](#xss-match-statement) below for details.

### AND Statement

A logical rule statement used to combine other rule statements with `AND` logic. You provide more than one `statement` within the `and_statement`.

The `and_statement` block supports the following arguments:

* `statement` - (Required) The statements to combine with `AND` logic. You can use any statements that can be nested. See [Statement](#statement) above for details.

### Byte Match Statement

The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters.

The `byte_match_statement` block supports the following arguments:

* `field_to_match` - (Optional) The part of a web request that you want AWS WAF to inspect. See [Field to Match](#field-to-match) below for details.
* `positional_constraint` - (Required) The area within the portion of a web request that you want AWS WAF to search for `search_string`. Valid values include the following: `EXACTLY`, `STARTS_WITH`, `ENDS_WITH`, `CONTAINS`, `CONTAINS_WORD`. See the AWS [documentation](https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchStatement.html) for more information.
* `search_string` - (Required) A string value that you want AWS WAF to search for. AWS WAF searches only in the part of web requests that you designate for inspection in `field_to_match`. The maximum length of the value is 50 bytes.
* `text_transformation` - (Required) Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. See [Text Transformation](#text-transformation) below for details.


### GEO Match Statement

The `geo_match_statement` block supports the following arguments:

* `country_codes` - (Required) An array of two-character country codes, for example, [ "US", "CN" ], from the alpha-2 country ISO codes of the `ISO 3166` international standard. See the [documentation](https://docs.aws.amazon.com/waf/latest/APIReference/API_GeoMatchStatement.html) for valid values.
* `forwarded_ip_config` - (Optional) The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. See [Forwarded IP Config](#forwarded-ip-config) below for details.

### IP Set Reference Statement

A rule statement used to detect web requests coming from particular IP addresses or address ranges. To use this, create an `aws_wafv2_ip_set` that specifies the addresses you want to detect, then use the `ARN` of that set in this statement.

The `ip_set_reference_statement` block supports the following arguments:

* `arn` - (Required) The Amazon Resource Name (ARN) of the IP Set that this statement references.
* `ip_set_forwarded_ip_config` - (Optional) The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. See [IPSet Forwarded IP Config](#ipset-forwarded-ip-config) below for more details.

### Managed Rule Group Statement

A rule statement used to run the rules that are defined in a managed rule group.

You can't nest a `managed_rule_group_statement`, for example for use inside a `not_statement` or `or_statement`. It can only be referenced as a `top-level` statement within a `rule`.

The `managed_rule_group_statement` block supports the following arguments:

* `excluded_rule` - (Optional) The `rules` whose actions are set to `COUNT` by the web ACL, regardless of the action that is set on the rule. See [Excluded Rule](#excluded-rule) below for details.
* `name` - (Required) The name of the managed rule group.
* `vendor_name` - (Required) The name of the managed rule group vendor.

### NOT Statement

A logical rule statement used to negate the results of another rule statement. You provide one `statement` within the `not_statement`.

The `not_statement` block supports the following arguments:

* `statement` - (Required) The statement to negate. You can use any statement that can be nested. See [Statement](#statement) above for details.

### OR Statement

A logical rule statement used to combine other rule statements with `OR` logic. You provide more than one `statement` within the `or_statement`.

The `or_statement` block supports the following arguments:

* `statement` - (Required) The statements to combine with `OR` logic. You can use any statements that can be nested. See [Statement](#statement) above for details.

### Rate Based Statement

A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span. You can use this to put a temporary block on requests from an IP address that is sending excessive requests. See the [documentation](https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html) for more information.

You can't nest a `rate_based_statement`, for example for use inside a `not_statement` or `or_statement`. It can only be referenced as a `top-level` statement within a `rule`.

The `rate_based_statement` block supports the following arguments:

* `aggregate_key_type` - (Optional) Setting that indicates how to aggregate the request counts. Valid values include: `FORWARDED_IP` or `IP`. Default: `IP`.
* `forwarded_ip_config` - (Optional) The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. If `aggregate_key_type` is set to `FORWARDED_IP`, this block is required. See [Forwarded IP Config](#forwarded-ip-config) below for details.
* `limit` - (Required) The limit on requests per 5-minute period for a single originating IP address.
* `scope_down_statement` - (Optional) An optional nested statement that narrows the scope of the rate-based statement to matching web requests. This can be any nestable statement, and you can nest statements at any level below this scope-down statement. See [Statement](#statement) above for details.

### Regex Pattern Set Reference Statement

A rule statement used to search web request components for matches with regular expressions. To use this, create a `aws_wafv2_regex_pattern_set` that specifies the expressions that you want to detect, then use the `ARN` of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set.

The `regex_pattern_set_reference_statement` block supports the following arguments:

* `arn` - (Required) The Amazon Resource Name (ARN) of the Regex Pattern Set that this statement references.
* `field_to_match` - (Optional) The part of a web request that you want AWS WAF to inspect. See [Field to Match](#field-to-match) below for details.
* `text_transformation` - (Required) Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. See [Text Transformation](#text-transformation) below for details.

### Rule Group Reference Statement

A rule statement used to run the rules that are defined in an WAFv2 Rule Group or `aws_wafv2_rule_group` resource.

You can't nest a `rule_group_reference_statement`, for example for use inside a `not_statement` or `or_statement`. It can only be referenced as a `top-level` statement within a `rule`.

The `rule_group_reference_statement` block supports the following arguments:

* `arn` - (Required) The Amazon Resource Name (ARN) of the `aws_wafv2_rule_group` resource.
* `excluded_rule` - (Optional) The `rules` whose actions are set to `COUNT` by the web ACL, regardless of the action that is set on the rule. See [Excluded Rule](#excluded-rule) below for details.

### Size Constraint Statement

A rule statement that uses a comparison operator to compare a number of bytes against the size of a request component. AWS WAFv2 inspects up to the first 8192 bytes (8 KB) of a request body, and when inspecting the request URI Path, the slash `/` in
the URI counts as one character.

The `size_constraint_statement` block supports the following arguments:

* `comparison_operator` - (Required) The operator to use to compare the request part to the size setting. Valid values include: `EQ`, `NE`, `LE`, `LT`, `GE`, or `GT`.
* `field_to_match` - (Optional) The part of a web request that you want AWS WAF to inspect. See [Field to Match](#field-to-match) below for details.
* `size` - (Required) The size, in bytes, to compare to the request part, after any transformations. Valid values are integers between 0 and 21474836480, inclusive.
* `text_transformation` - (Required) Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. See [Text Transformation](#text-transformation) below for details.

### SQL Injection Match Statement

An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.

The `sqli_match_statement` block supports the following arguments:

* `field_to_match` - (Optional) The part of a web request that you want AWS WAF to inspect. See [Field to Match](#field-to-match) below for details.
* `text_transformation` - (Required) Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. See [Text Transformation](#text-transformation) below for details.

### XSS Match Statement

The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

The `xss_match_statement` block supports the following arguments:

* `field_to_match` - (Optional) The part of a web request that you want AWS WAF to inspect. See [Field to Match](#field-to-match) below for details.
* `text_transformation` - (Required) Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. See [Text Transformation](#text-transformation) below for details.

### Excluded Rule

The `excluded_rule` block supports the following arguments:

* `name` - (Required) The name of the rule to exclude. If the rule group is managed by AWS, see the [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html) for a list of names in the appropriate rule group in use.

### Field to Match

The part of a web request that you want AWS WAF to inspect. Include the single `field_to_match` type that you want to inspect, with additional specifications as needed, according to the type. You specify a single request component in `field_to_match` for each rule statement that requires it. To inspect more than one component of a web request, create a separate rule statement for each component. See the [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields.html#waf-rule-statement-request-component) for more details.

The `field_to_match` block supports the following arguments:

~> **NOTE:** Only one of `all_query_arguments`, `body`, `method`, `query_string`, `single_header`, `single_query_argument`, or `uri_path` can be specified.
An empty configuration block `{}` should be used when specifying `all_query_arguments`, `body`, `method`, or `query_string` attributes.

* `all_query_arguments` - (Optional) Inspect all query arguments.
* `body` - (Optional) Inspect the request body, which immediately follows the request headers.
* `method` - (Optional) Inspect the HTTP method. The method indicates the type of operation that the request is asking the origin to perform.
* `query_string` - (Optional) Inspect the query string. This is the part of a URL that appears after a `?` character, if any.
* `single_header` - (Optional) Inspect a single header. See [Single Header](#single-header) below for details.
* `single_query_argument` - (Optional) Inspect a single query argument. See [Single Query Argument](#single-query-argument) below for details.
* `uri_path` - (Optional) Inspect the request URI path. This is the part of a web request that identifies a resource, for example, `/images/daily-ad.jpg`.

### Forwarded IP Config

The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify
any header name. If the specified header isn't present in the request, AWS WAFv2 doesn't apply the rule to the web request at all.
AWS WAFv2 only evaluates the first IP address found in the specified HTTP header.

The `forwarded_ip_config` block supports the following arguments:

* `fallback_behavior` - (Required) - The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. Valid values include: `MATCH` or `NO_MATCH`.
* `header_name` - (Required) - The name of the HTTP header to use for the IP address.

### IPSet Forwarded IP Config

The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.

The `ip_set_forwarded_ip_config` block supports the following arguments:

* `fallback_behavior` - (Required) - The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. Valid values include: `MATCH` or `NO_MATCH`.
* `header_name` - (Required) - The name of the HTTP header to use for the IP address.
* `position` - (Required) - The position in the header to search for the IP address. Valid values include: `FIRST`, `LAST`, or `ANY`. If `ANY` is specified and the header contains more than 10 IP addresses, AWS WAFv2 inspects the last 10.

### Single Header

Inspect a single header. Provide the name of the header to inspect, for example, `User-Agent` or `Referer` (provided as lowercase strings).

The `single_header` block supports the following arguments:

* `name` - (Optional) The name of the query header to inspect. This setting must be provided as lower case characters.

### Single Query Argument

Inspect a single query argument. Provide the name of the query argument to inspect, such as `UserName` or `SalesRegion` (provided as lowercase strings).

The `single_query_argument` block supports the following arguments:

* `name` - (Optional) The name of the query header to inspect. This setting must be provided as lower case characters.

### Text Transformation

The `text_transformation` block supports the following arguments:

* `priority` - (Required) The relative processing order for multiple transformations that are defined for a rule statement. AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content.
* `type` - (Required) The transformation to apply, you can specify the following types: `NONE`, `COMPRESS_WHITE_SPACE`, `HTML_ENTITY_DECODE`, `LOWERCASE`, `CMD_LINE`, `URL_DECODE`. See the [documentation](https://docs.aws.amazon.com/waf/latest/APIReference/API_TextTransformation.html) for more details.

### Visibility Configuration

The `visibility_config` block supports the following arguments:

* `cloudwatch_metrics_enabled` - (Required) A boolean indicating whether the associated resource sends metrics to CloudWatch. For the list of available metrics, see [AWS WAF Metrics](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics).
* `metric_name` - (Required) A friendly name of the CloudWatch metric. The name can contain only alphanumeric characters (A-Z, a-z, 0-9) hyphen(-) and underscore (\_), with length from one to 128 characters. It can't contain whitespace or metric names reserved for AWS WAF, for example `All` and `Default_Action`.
* `sampled_requests_enabled` - (Required) A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the AWS WAF console.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `arn` - The ARN of the WAF WebACL.
* `capacity` - The web ACL capacity units (WCUs) currently being used by this web ACL.
* `id` - The ID of the WAF WebACL.
* `tags_all` - A map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).
