# =========================================================================== #
#             Apache2.0 Copyright (c) 2022 Kris Nóva <krisnova@krisnova.net>       #
#                                                                             #
#                 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                 #
#                 ┃   ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗   ┃                 #
#                 ┃   ████╗  ██║██╔═████╗██║   ██║██╔══██╗  ┃                 #
#                 ┃   ██╔██╗ ██║██║██╔██║██║   ██║███████║  ┃                 #
#                 ┃   ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║  ┃                 #
#                 ┃   ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║  ┃                 #
#                 ┃   ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝  ┃                 #
#                 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                 #
#                                                                             #
#                        This machine kills fascists.                         #
#                                                                             #
# =========================================================================== #

all: compile

CC           ?= clang
TARGET       ?= tcpjack
CFLAGS       ?= -I/usr/include -I./include -L/usr/lib -g
LDFLAGS      ?=
LIBS         ?= -lnet -lpcap
STYLE         = Google

compile: ## Compile for the local architecture ⚙
	@$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $(TARGET) src/tcpjack.c src/list.c src/proc.c

install: ## Install the program to /usr/bin 🎉
	@echo "Installing..."

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
