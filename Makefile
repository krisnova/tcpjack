# =========================================================================== #
#             Apache2.0 Copyright (c) 2022 Kris Nóva <kris@nivenly.com>       #
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

TARGET       ?=  tcpjack
CFLAGS       ?= -I/usr/include -I./include -g
LDFLAGS      ?=
LIBS         ?=
STYLE         = Google

compile: ## Compile for the local architecture ⚙
	gcc $(CFLAGS) $(LDFLAGS) $(LIBS) -static -o $(TARGET) src/tcpjack.c

install: ## Install the program to /usr/bin 🎉
	@echo "Installing..."

clean: ## Clean your artifacts 🧼
	@echo "Cleaning..."
	@rm -rvf $(TARGET)

format: ## Format the code
	@echo "  ->  Formatting code"
	@clang-format -i -style=$(STYLE) src/*.c src/*.h
	@clang-format -i -style=$(STYLE) include/*.c include/*.h

.PHONY: help
help:  ## 🤔 Show help messages for make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'
