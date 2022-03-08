#!/bin/bash

if [[ -z $1 ]];
then
	echo "You must indicate the program number"
	exit 123
else
	echo "Fuzzing ./prog_$1"
fi

start=`date +%s%N`

prng_seed=$((10000+$RANDOM%1000000))
echo "Using $prng_seed as PRNG seed"

for i in {1..20000}; do
	echo -ne "prng_seed=$prng_seed, iter=$i\r"

#	cat seed | ./fuzzer "$prng_seed" "$i" -p | tee myoutput | ./prog_$1 || {
#	cat seed | ./fuzzer "$prng_seed" "$i" -p | ./prog_$1 || {
	./fuzzer "$prng_seed" "$i" -0 | ./prog_$1 2>/dev/null || {
		status=$?
		if [ "$status" -eq 139 ]; then
			end=`date +%s%N`
			break
		fi
	}
done
printf "Done $i iterations in %0.2f seconds." $(echo "scale=2;($end-$start)/1000000000" | bc)

