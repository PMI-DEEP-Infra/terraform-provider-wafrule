# Terraform Provider for adding WAF rule to ACLs created by AWS Firewall Manager

The main idea for creation of this provider is a fact that Firewall Manager creates a copy of globally defined WAF ACL policy and as this local copy is not created by Terraform there is no way to add rules there using AWS provider while still there is a need to define account level rules with Terraform.
The provider is based on the AWS provider WAF related source code https://github.com/hashicorp/terraform-provider-aws/, but re-worked to allow create/update/delete account level rules.

# Provider build

```
$ go build -o terraform-provider-wafrule
$ terraform init
$ terraform plan
$ terraform apply
```
