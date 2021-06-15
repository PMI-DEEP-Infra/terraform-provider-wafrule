package wafrule

import (
  "github.com/aws/aws-sdk-go/aws"
  "github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
   "gopkg.in/yaml.v2"
)


func expandStringList(configured []interface{}) []*string {
  vs := make([]*string, 0, len(configured))
  for _, v := range configured {
    val, ok := v.(string)
    if ok && val != "" {
      vs = append(vs, aws.String(v.(string)))
    }
  }
  return vs
}


func flattenStringList(list []*string) []interface{} {
  vs := make([]interface{}, 0, len(list))
  for _, v := range list {
    vs = append(vs, *v)
  }
  return vs
}


func checkYamlString(yamlString interface{}) (string, error) {
  var y interface{}

  if yamlString == nil || yamlString.(string) == "" {
    return "", nil
  }

  s := yamlString.(string)

  err := yaml.Unmarshal([]byte(s), &y)

  return s, err
}


func normalizeJsonOrYamlString(templateString interface{}) (string, error) {
  if looksLikeJsonString(templateString) {
    return structure.NormalizeJsonString(templateString.(string))
  }

  return checkYamlString(templateString)
}
