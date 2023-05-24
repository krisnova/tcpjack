###############################################################################
#                                                                             #
#                     ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     #
#                     ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    #
#                     ██╔██╗ ██║██║   ██║██║   ██║███████║                    #
#                     ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    #
#                     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    #
#                     ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    #
#               Written By: Kris Nóva    <admin@krisnova.net>                 #
#                                                                             #
###############################################################################

CC           ?= clang
TARGET       ?= tcpjack
DESTDIR      ?= /usr/bin
CFLAGS       ?= -I/usr/include -I./include -L/usr/lib -g -O0
LDFLAGS      ?=
LIBS         ?= -lnet -lpcap
STYLE        ?= Google
SOURCES      ?= src/tcpjack.c src/list.c src/proc.c src/trace.c src/packet.c

default: tcpjack
all:     tcpjack install

.PHONY: tcpjack
tcpjack: ## Compile for the local architecture ⚙
	@$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $(TARGET) $(SOURCES)

install: ## Install the program to /usr/bin 🎉
	@echo "Installing..."
	install -m 755 $(TARGET) $(DESTDIR)/$(TARGET)

clean: ## Clean your artifacts 🧼
	@echo "Cleaning..."
	@rm -rvf $(TARGET)

format: ## Format the code
	@echo "  ->  Formatting code"
	@clang-format -i -style=$(STYLE) ./src/*.c
	@clang-format -i -style=$(STYLE)  ./include/*.h

.PHONY: help
help:  ## 🤔 Show help messages for make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'
