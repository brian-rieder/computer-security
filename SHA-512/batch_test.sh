#!/bin/bash

echo "Testing hash function..."
successes=0
testcases=10

for i in $(seq 1 $testcases) ; do
  echo "=================================================="
  echo "Test Case $i: "
  echo ""
  fortune | tee tmp.txt
  echo ""
  output=$(hw07.py tmp.txt)
  cat output.hex
  expected=$(echo "Hash matches 'hashlib' hex digest!")
  diff <(echo $output) <(echo $expected)
  echo ""
  if [ $? -eq 0 ] ; then
    printf "\033[0;32mPASSED\n\033[0m"
    (( successes += 1 ))
  else
    printf "\033[0;31mFAILED\n\033[0m"
  fi
done
echo "=================================================="
rm tmp.txt
echo "Results: $successes / $testcases"
