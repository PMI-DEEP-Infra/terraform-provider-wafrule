package verify

import (
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws/arn"
)

var accountIDRegexp = regexp.MustCompile(`^(aws|aws-managed|\d{12})$`)
var partitionRegexp = regexp.MustCompile(`^aws(-[a-z]+)*$`)
var regionRegexp = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)

func ValidARN(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if value == "" {
		return ws, errors
	}

	parsedARN, err := arn.Parse(value)

	if err != nil {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: %s", k, value, err))
		return ws, errors
	}

	if parsedARN.Partition == "" {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing partition value", k, value))
	} else if !partitionRegexp.MatchString(parsedARN.Partition) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid partition value (expecting to match regular expression: %s)", k, value, partitionRegexp))
	}

	if parsedARN.Region != "" && !regionRegexp.MatchString(parsedARN.Region) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid region value (expecting to match regular expression: %s)", k, value, regionRegexp))
	}

	if parsedARN.AccountID != "" && !accountIDRegexp.MatchString(parsedARN.AccountID) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid account ID value (expecting to match regular expression: %s)", k, value, accountIDRegexp))
	}

	if parsedARN.Resource == "" {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing resource value", k, value))
	}

	return ws, errors
}
