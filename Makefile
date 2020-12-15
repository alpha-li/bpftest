SUB_DIR =  bpf_lb lb

.PHONY: subdirs $(SUB_DIR) clean

all: $(SUB_DIR)

$(SUB_DIR):
	@+make -C $@

clean:
	for dir in $(SUB_DIR); do \
		make -C $$dir clean; \
	done