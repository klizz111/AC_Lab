./install.sh

./bin/bin/verifier - 5 > verifier_log.txt &

./bin/bin/prover - - 5 - > prover_log.txt &

wait