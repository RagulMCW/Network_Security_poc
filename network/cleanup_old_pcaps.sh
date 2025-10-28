#!/bin/bash
# Cleanup old PCAP files - keep only the 4 most recent

CAP_DIR="/mnt/e/nos/Network_Security_poc/network/captures"
KEEP_COUNT=4

echo "=========================================="
echo "PCAP File Cleanup Script"
echo "=========================================="

# Count total files
TOTAL=$(ls -1 "${CAP_DIR}"/*.pcap 2>/dev/null | wc -l)
echo "Total PCAP files: ${TOTAL}"

if [ "${TOTAL}" -le "${KEEP_COUNT}" ]; then
    echo "✓ No cleanup needed (${TOTAL} files, keeping ${KEEP_COUNT})"
    exit 0
fi

# List files to be deleted
echo ""
echo "Files to DELETE (oldest first):"
ls -1t "${CAP_DIR}"/*.pcap | tail -n +$((KEEP_COUNT + 1)) | while read file; do
    SIZE=$(stat -f %z "$file" 2>/dev/null || stat -c %s "$file" 2>/dev/null)
    echo "  - $(basename "$file") (${SIZE} bytes)"
done

echo ""
echo "Files to KEEP (newest 4):"
ls -1t "${CAP_DIR}"/*.pcap | head -n ${KEEP_COUNT} | while read file; do
    SIZE=$(stat -f %z "$file" 2>/dev/null || stat -c %s "$file" 2>/dev/null)
    echo "  ✓ $(basename "$file") (${SIZE} bytes)"
done

echo ""
read -p "Delete $((TOTAL - KEEP_COUNT)) old files? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Delete old files
    DELETED=0
    ls -1t "${CAP_DIR}"/*.pcap | tail -n +$((KEEP_COUNT + 1)) | while read file; do
        rm -f "$file"
        DELETED=$((DELETED + 1))
        echo "  Deleted: $(basename "$file")"
    done
    
    echo ""
    echo "✓ Cleanup complete! Deleted $((TOTAL - KEEP_COUNT)) files, kept ${KEEP_COUNT}"
else
    echo "Cleanup cancelled"
fi

echo "=========================================="
