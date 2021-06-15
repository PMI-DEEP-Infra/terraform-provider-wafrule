# wafrule Provider

## Schema

### Optional

- **access_key** (String) The access key for API operations. You can retrieve this
from the 'Security & Credentials' section of the AWS console.
- **assume_role** (Block List, Max: 1) (see [below for nested schema](#nestedblock--assume_role))
- **insecure** (Boolean) Explicitly allow the provider to perform "insecure" SSL requests. If omitted, default value is `false`
- **max_retries** (Number) The maximum number of times an AWS API request is
being executed. If the API request still fails, an error is
thrown.
- **profile** (String) The profile for API operations. If not set, the default profile
created with `aws configure` will be used.
- **region** (String) The region where AWS operations will take place. Examples
are us-east-1, us-west-2, etc.
- **secret_key** (String) The secret key for API operations. You can retrieve this
from the 'Security & Credentials' section of the AWS console.
- **shared_credentials_file** (String) The path to the shared credentials file. If not set
this defaults to ~/.aws/credentials.
- **skip_credentials_validation** (Boolean) Skip the credentials validation via STS API. Used for AWS API implementations that do not have STS available/implemented.
- **skip_metadata_api_check** (Boolean)
- **skip_region_validation** (Boolean) Skip static validation of region name. Used by users of alternative AWS-like APIs or users w/ access to regions that are not public (yet).
- **skip_requesting_account_id** (Boolean) Skip requesting the account ID. Used for AWS API implementations that do not have IAM/STS API and/or metadata API.
- **token** (String) session token. A session token is only required if you are
using temporary security credentials.

<a id="nestedblock--assume_role"></a>
### Nested Schema for `assume_role`

Optional:

- **duration_seconds** (Number) Seconds to restrict the assume role session duration.
- **external_id** (String) Unique identifier that might be required for assuming a role in another account.
- **policy** (String) IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.
- **policy_arns** (Set of String) Amazon Resource Names (ARNs) of IAM Policies describing further restricting permissions for the IAM Role being assumed.
- **role_arn** (String) Amazon Resource Name of an IAM Role to assume prior to making API calls.
- **session_name** (String) Identifier for the assumed role session.
- **tags** (Map of String) Assume role session tags.
- **transitive_tag_keys** (Set of String) Assume role session tag keys to pass to any subsequent sessions.
