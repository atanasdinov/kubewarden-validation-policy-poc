#!/usr/bin/env bats

@test "accept when no settings are provided" {
  run kwctl run -r test_data/pod.json annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request is accepted
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "accept when label is satisfying a constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/pod.json \
    --settings-json '{"constrained_labels": {"cc-center": "\\d+"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept when labels are not on deny list" {
  run kwctl run \
    -r test_data/pod.json \
    --settings-json '{"denied_labels": ["foo", "bar"]}' \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "reject when label is on deny list" {
  run kwctl run annotated-policy.wasm \
    -r test_data/pod.json \
    --settings-json '{"denied_labels": ["foo", "owner"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*label .*"owner.*" is on the deny list.*") -ne 0 ]
}

@test "reject when label is not satisfying a constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/pod.json \
    --settings-json '{"constrained_labels": {"cc-center": "team-\\d+"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*label .*"cc-center.*" does not pass user-defined constraint.*") -ne 0 ]
}

@test "reject when constrained label is missing" {
  run kwctl run annotated-policy.wasm \
    -r test_data/pod.json \
    --settings-json '{"constrained_labels": {"organization": "\\d+"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*constrained label .*organization.* not found inside of Pod.*") -ne 0 ]
}

@test "fail settings validation because of conflicting labels" {
  run kwctl run \
    -r test_data/pod.json \
    --settings-json '{"denied_labels": ["foo", "cc-center"], "constrained_labels": {"cc-center": "^cc-\\d+$"}}' \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation failed
  [ $(expr "$output" : '.*"valid":false.*') -ne 0 ]
  [ $(expr "$output" : ".*Provided settings are not valid: the following labels cannot be constrained and denied at the same time: Set{cc-center}.*") -ne 0 ]
}

@test "fail settings validation because of invalid constraint" {
  run kwctl run \
    -r test_data/pod.json \
    --settings-json '{"constrained_labels": {"cc-center": "^cc-[12$"}}' \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ $(expr "$output" : '.*"valid":false.*') -ne 0 ]
  [ $(expr "$output" : ".*Provided settings are not valid: compiling regexp.*") -ne 0 ]
}
