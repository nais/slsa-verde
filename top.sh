#!/bin/bash

# Check if NAMESPACE and POD_PREFIX are set
if [ -z "$NAMESPACE" ] || [ -z "$POD_PREFIX" ]; then
    echo "Please set NAMESPACE and POD_PREFIX environment variables."
    exit 1
fi

# Get the first pod matching the prefix
POD_NAME=$(kubectl get pods -n $NAMESPACE --no-headers | awk -v prefix="$POD_PREFIX" '$1 ~ "^"prefix {print $1; exit}')

if [ -z "$POD_NAME" ]; then
    echo "No pod found with prefix $POD_PREFIX in namespace $NAMESPACE."
    exit 1
fi

echo "Monitoring pod: $POD_NAME in namespace: $NAMESPACE"

# Initialize variables for cumulative, top, and low CPU and memory values, and count
total_cpu=0
total_memory=0
count=0
start_time=$(date +%s)

# Initialize top and low values with empty values
top_cpu=0
low_cpu=""
top_memory=0
low_memory=""

# Function to calculate and print average, top, and low CPU and memory usage, including total runtime
function print_summary {
    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))

    if [ $count -gt 0 ]; then
        avg_cpu=$(echo "$total_cpu / $count" | bc)
        avg_memory=$(echo "$total_memory / $count" | bc)
        echo "Average CPU: ${avg_cpu}m"
        echo "Average Memory: ${avg_memory}Mi"
        echo "Top CPU: ${top_cpu}m, Low CPU: ${low_cpu}m"
        echo "Top Memory: ${top_memory}Mi, Low Memory: ${low_memory}Mi"
        echo "Total runtime: ${elapsed_time} seconds"
    else
        echo "No data collected."
    fi
}

# Trap to ensure the summary is printed before exit
trap print_summary EXIT

# Monitor `kubectl top` output every 10 seconds
while true; do
    echo "Timestamp: $(date)"

    # Get CPU and memory usage
    output=$(kubectl top pod $POD_NAME -n $NAMESPACE --no-headers)

    if [ -z "$output" ]; then
        echo "Failed to retrieve data for $POD_NAME. Retrying..."
        sleep 10
        continue
    fi

    # Extract CPU and memory usage
    cpu=$(echo $output | awk '{print $2}' | sed 's/m//')
    memory=$(echo $output | awk '{print $3}' | sed 's/Mi//')

    # Add to cumulative totals and increment count
    total_cpu=$((total_cpu + cpu))
    total_memory=$((total_memory + memory))
    count=$((count + 1))

    # Update top and low CPU values
    if [ -z "$low_cpu" ] || [ $cpu -lt $low_cpu ]; then
        low_cpu=$cpu
    fi
    if [ $cpu -gt $top_cpu ]; then
        top_cpu=$cpu
    fi

    # Update top and low Memory values
    if [ -z "$low_memory" ] || [ $memory -lt $low_memory ]; then
        low_memory=$memory
    fi
    if [ $memory -gt $top_memory ]; then
        top_memory=$memory
    fi

    echo "CPU: ${cpu}m, Memory: ${memory}Mi"
    sleep 10
done
