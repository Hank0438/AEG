# AEG

## Feature
* solve non-determined menu-type
* detect and exploit heap vulnerable model in how2heap
* use bounded model which motivated by heaphopper
* merge and update scripts in Zerotool

#### Specify vulnerabilities to detect: 
+ arbitrary write
+ allocations over already allocated memory
+ allocations over non-heap-memory
+ freeing of fake chunks

## Input Source
* input-type: STDIN
* input-type: ARG
* input-type: LIBPWNABLE

## Usage and Test case

### Buffer Overflow

### Format String

### Use After Free
* check if free chunk mem_write
* check if free chunk free (Double Free)

### Heap Overflow (off-one-by-null)
* check if malloc chunk header overwrite

### Heap Overlap
* check if malloc chunks (header_size + size) and addr

### Free Fake Chunk
* check if free non_chunk addr

### Arbitary Relative Write


### Single Bitflip
