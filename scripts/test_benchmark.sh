#!/bin/bash
# Quick test script for benchmark

echo "=== Testing DNS Covert Channel Benchmark ==="
echo ""

# Test 1: All metrics
echo "[Test 1] Running all metrics..."
python3 scripts/run_benchmark.py --all --verbose

echo ""
echo "[Test 2] Running only throughput and latency..."
python3 scripts/run_benchmark.py --throughput --latency

echo ""
echo "[Test 3] Custom configuration..."
python3 scripts/run_benchmark.py --all \
  --test-file dnssec-covert_LAN/test_lan_data.bin \
  --output-json benchmark_results/custom_test.json \
  --ping-count 100

echo ""
echo "=== Tests completed! Check benchmark_results/ for output ==="
