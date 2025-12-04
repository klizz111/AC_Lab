./install.sh

./bin/bin/verifier - - > verifier_log.txt &

./bin/bin/prover - - - - > prover_log.txt &

wait