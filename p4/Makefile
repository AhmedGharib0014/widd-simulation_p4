# WIDD P4 Makefile
# Compiles widd.p4 to JSON for bmv2 simple_switch

P4C = p4c-bm2-ss
P4_SOURCE = widd.p4
P4_JSON = widd.json
P4_INFO = widd.p4i

.PHONY: all clean

all: $(P4_JSON)

$(P4_JSON): $(P4_SOURCE)
	$(P4C) --p4v 16 -o $(P4_JSON) $(P4_SOURCE)
	@echo "Compiled $(P4_SOURCE) -> $(P4_JSON)"

clean:
	rm -f $(P4_JSON) $(P4_INFO)
	@echo "Cleaned build artifacts"

# Compile with debug info
debug: $(P4_SOURCE)
	$(P4C) --p4v 16 -o $(P4_JSON) --p4runtime-files $(P4_INFO) $(P4_SOURCE)
	@echo "Compiled $(P4_SOURCE) with debug info"
