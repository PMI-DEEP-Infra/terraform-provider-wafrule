package wafrule

import (
  "log"
  "strings"

  "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
  "github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
  "github.com/terraform-providers/terraform-provider-wafrule/wafrule/internal/mutexkv"
)

// Provider returns a *schema.Provider.
func Provider() *schema.Provider {
  // TODO: Move the validation to this, requires conditional schemas
  // TODO: Move the configuration to this, requires validation

  // The actual provider
  provider := &schema.Provider{
    Schema: map[string]*schema.Schema{
      "access_key": {
        Type:        schema.TypeString,
        Optional:    true,
        Default:     "",
        Description: descriptions["access_key"],
      },

      "secret_key": {
        Type:        schema.TypeString,
        Optional:    true,
        Default:     "",
        Description: descriptions["secret_key"],
      },

      "profile": {
        Type:        schema.TypeString,
        Optional:    true,
        Default:     "",
        Description: descriptions["profile"],
      },

      "assume_role": assumeRoleSchema(),

      "shared_credentials_file": {
        Type:        schema.TypeString,
        Optional:    true,
        Default:     "",
        Description: descriptions["shared_credentials_file"],
      },

      "token": {
        Type:        schema.TypeString,
        Optional:    true,
        Default:     "",
        Description: descriptions["token"],
      },

      "region": {
        Type:     schema.TypeString,
        Required: true,
        DefaultFunc: schema.MultiEnvDefaultFunc([]string{
          "AWS_REGION",
          "AWS_DEFAULT_REGION",
        }, nil),
        Description:  descriptions["region"],
        InputDefault: "us-east-1", // lintignore:AWSAT003
      },

      "max_retries": {
        Type:        schema.TypeInt,
        Optional:    true,
        Default:     25,
        Description: descriptions["max_retries"],
      },

      "insecure": {
        Type:        schema.TypeBool,
        Optional:    true,
        Default:     false,
        Description: descriptions["insecure"],
      },

      "skip_credentials_validation": {
        Type:        schema.TypeBool,
        Optional:    true,
        Default:     false,
        Description: descriptions["skip_credentials_validation"],
      },

      "skip_region_validation": {
        Type:        schema.TypeBool,
        Optional:    true,
        Default:     false,
        Description: descriptions["skip_region_validation"],
      },

      "skip_requesting_account_id": {
        Type:        schema.TypeBool,
        Optional:    true,
        Default:     false,
        Description: descriptions["skip_requesting_account_id"],
      },

      "skip_metadata_api_check": {
        Type:        schema.TypeBool,
        Optional:    true,
        Default:     false,
        Description: descriptions["skip_metadata_api_check"],
      },

    },

    ResourcesMap: map[string]*schema.Resource{
      "wafrule_acl_rule": resourceAwsWafv2Rules(),
    },
  }


  provider.ConfigureFunc = func(d *schema.ResourceData) (interface{}, error) {
    terraformVersion := provider.TerraformVersion
    if terraformVersion == "" {
      // Terraform 0.12 introduced this field to the protocol
      // We can therefore assume that if it's missing it's 0.10 or 0.11
      terraformVersion = "0.11+compatible"
    }
    return providerConfigure(d, terraformVersion)
  }

  return provider
}

var descriptions map[string]string


func init() {
  descriptions = map[string]string{
    "region": "The region where AWS operations will take place. Examples\n" +
      "are us-east-1, us-west-2, etc.", // lintignore:AWSAT003

    "access_key": "The access key for API operations. You can retrieve this\n" +
      "from the 'Security & Credentials' section of the AWS console.",

    "secret_key": "The secret key for API operations. You can retrieve this\n" +
      "from the 'Security & Credentials' section of the AWS console.",

    "profile": "The profile for API operations. If not set, the default profile\n" +
      "created with `aws configure` will be used.",

    "shared_credentials_file": "The path to the shared credentials file. If not set\n" +
      "this defaults to ~/.aws/credentials.",

    "token": "session token. A session token is only required if you are\n" +
      "using temporary security credentials.",

    "max_retries": "The maximum number of times an AWS API request is\n" +
      "being executed. If the API request still fails, an error is\n" +
      "thrown.",

    "insecure": "Explicitly allow the provider to perform \"insecure\" SSL requests. If omitted," +
      "default value is `false`",

    "skip_credentials_validation": "Skip the credentials validation via STS API. " +
      "Used for AWS API implementations that do not have STS available/implemented.",

    "skip_region_validation": "Skip static validation of region name. " +
      "Used by users of alternative AWS-like APIs or users w/ access to regions that are not public (yet).",

    "skip_requesting_account_id": "Skip requesting the account ID. " +
      "Used for AWS API implementations that do not have IAM/STS API and/or metadata API.",

    "skip_medatadata_api_check": "Skip the AWS Metadata API check. " +
      "Used for AWS API implementations that do not have a metadata api endpoint.",
  }
}

func providerConfigure(d *schema.ResourceData, terraformVersion string) (interface{}, error) {
  config := Config{
    AccessKey:               d.Get("access_key").(string),
    SecretKey:               d.Get("secret_key").(string),
    Profile:                 d.Get("profile").(string),
    Token:                   d.Get("token").(string),
    Region:                  d.Get("region").(string),
    CredsFilename:           d.Get("shared_credentials_file").(string),
    Endpoints:               make(map[string]string),
    MaxRetries:              d.Get("max_retries").(int),
    Insecure:                d.Get("insecure").(bool),
    SkipCredsValidation:     d.Get("skip_credentials_validation").(bool),
    SkipRegionValidation:    d.Get("skip_region_validation").(bool),
    SkipRequestingAccountId: d.Get("skip_requesting_account_id").(bool),
    SkipMetadataApiCheck:    d.Get("skip_metadata_api_check").(bool),
    terraformVersion:        terraformVersion,
  }

  if l, ok := d.Get("assume_role").([]interface{}); ok && len(l) > 0 && l[0] != nil {
    m := l[0].(map[string]interface{})

    if v, ok := m["duration_seconds"].(int); ok && v != 0 {
      config.AssumeRoleDurationSeconds = v
    }

    if v, ok := m["external_id"].(string); ok && v != "" {
      config.AssumeRoleExternalID = v
    }

    if v, ok := m["policy"].(string); ok && v != "" {
      config.AssumeRolePolicy = v
    }

    if policyARNSet, ok := m["policy_arns"].(*schema.Set); ok && policyARNSet.Len() > 0 {
      for _, policyARNRaw := range policyARNSet.List() {
        policyARN, ok := policyARNRaw.(string)

        if !ok {
          continue
        }

        config.AssumeRolePolicyARNs = append(config.AssumeRolePolicyARNs, policyARN)
      }
    }

    if v, ok := m["role_arn"].(string); ok && v != "" {
      config.AssumeRoleARN = v
    }

    if v, ok := m["session_name"].(string); ok && v != "" {
      config.AssumeRoleSessionName = v
    }

    if tagMapRaw, ok := m["tags"].(map[string]interface{}); ok && len(tagMapRaw) > 0 {
      config.AssumeRoleTags = make(map[string]string)

      for k, vRaw := range tagMapRaw {
        v, ok := vRaw.(string)

        if !ok {
          continue
        }

        config.AssumeRoleTags[k] = v
      }
    }

    if transitiveTagKeySet, ok := m["transitive_tag_keys"].(*schema.Set); ok && transitiveTagKeySet.Len() > 0 {
      for _, transitiveTagKeyRaw := range transitiveTagKeySet.List() {
        transitiveTagKey, ok := transitiveTagKeyRaw.(string)

        if !ok {
          continue
        }

        config.AssumeRoleTransitiveTagKeys = append(config.AssumeRoleTransitiveTagKeys, transitiveTagKey)
      }
    }

    log.Printf("[INFO] assume_role configuration set: (ARN: %q, SessionID: %q, ExternalID: %q)", config.AssumeRoleARN, config.AssumeRoleSessionName, config.AssumeRoleExternalID)
  }

  return config.Client()
}

// This is a global MutexKV for use within this plugin.
var awsMutexKV = mutexkv.NewMutexKV()

func assumeRoleSchema() *schema.Schema {
  return &schema.Schema{
    Type:     schema.TypeList,
    Optional: true,
    MaxItems: 1,
    Elem: &schema.Resource{
      Schema: map[string]*schema.Schema{
        "duration_seconds": {
          Type:        schema.TypeInt,
          Optional:    true,
          Description: "Seconds to restrict the assume role session duration.",
        },
        "external_id": {
          Type:        schema.TypeString,
          Optional:    true,
          Description: "Unique identifier that might be required for assuming a role in another account.",
        },
        "policy": {
          Type:         schema.TypeString,
          Optional:     true,
          Description:  "IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.",
          ValidateFunc: validation.StringIsJSON,
        },
        "policy_arns": {
          Type:        schema.TypeSet,
          Optional:    true,
          Description: "Amazon Resource Names (ARNs) of IAM Policies describing further restricting permissions for the IAM Role being assumed.",
          Elem: &schema.Schema{
            Type:         schema.TypeString,
            ValidateFunc: validateArn,
          },
        },
        "role_arn": {
          Type:         schema.TypeString,
          Optional:     true,
          Description:  "Amazon Resource Name of an IAM Role to assume prior to making API calls.",
          ValidateFunc: validateArn,
        },
        "session_name": {
          Type:        schema.TypeString,
          Optional:    true,
          Description: "Identifier for the assumed role session.",
        },
        "tags": {
          Type:        schema.TypeMap,
          Optional:    true,
          Description: "Assume role session tags.",
          Elem:        &schema.Schema{Type: schema.TypeString},
        },
        "transitive_tag_keys": {
          Type:        schema.TypeSet,
          Optional:    true,
          Description: "Assume role session tag keys to pass to any subsequent sessions.",
          Elem:        &schema.Schema{Type: schema.TypeString},
        },
      },
    },
  }
}


// ReverseDns switches a DNS hostname to reverse DNS and vice-versa.
func ReverseDns(hostname string) string {
  parts := strings.Split(hostname, ".")

  for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
    parts[i], parts[j] = parts[j], parts[i]
  }

  return strings.Join(parts, ".")
}
