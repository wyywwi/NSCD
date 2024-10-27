SUBDIRS = cli kernel
DOCKER_CONTAINER_NAME=firewall_test_container
MODULE_NAME=firewall.ko
SCRIPT=test_firewall.sh

.PHONY: all install clean setup load_module run_test cleanup

# 默认目标，执行全部步骤：编译 -> 环境设置 -> 模块加载 -> 测试运行 -> 清理
all: build setup install run_test cleanup

# 1. 编译 CLI 和 kernel 子目录
build:
	@echo "==> Building CLI and Kernel modules..."
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir; \
	done

# 2. 设置Docker环境
setup:
	@echo "==> Setting up Docker environment..."
	@if [ $$(docker ps -a -q -f name=$(DOCKER_CONTAINER_NAME)) ]; then \
		echo "A container with the name $(DOCKER_CONTAINER_NAME) already exists. Stopping and removing it..."; \
		docker stop $(DOCKER_CONTAINER_NAME) || true; \
		docker rm $(DOCKER_CONTAINER_NAME) || true; \
	fi
	@docker run -d --name $(DOCKER_CONTAINER_NAME) --network bridge --rm dockerpull.com/alpine sleep infinity
	@docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(DOCKER_CONTAINER_NAME) > container_ip.txt
	@echo "Docker container started. IP saved in container_ip.txt."

# 3. 加载内核模块
install:
	@echo "==> Loading kernel module..."
	@for subdir in $(SUBDIRS); do\
		$(MAKE) -C $$subdir install; \
	done

# 4. 运行测试脚本
run_test:
	@echo "==> Running firewall test script..."
	@if [ -f $(SCRIPT) ]; then \
		chmod +x $(SCRIPT); \
		./$(SCRIPT); \
	else \
		echo "Test script $(SCRIPT) not found."; \
	fi

# 5. 清理环境
cleanup:
	@echo "==> Cleaning up Docker container and unloading module..."
	@docker stop $(DOCKER_CONTAINER_NAME)
	@sudo rmmod $(MODULE_NAME) || echo "Module not loaded or unload failed"
	@rm -f container_ip.txt
	@$(MAKE) clean
	@echo "Cleanup complete."

# 清理子目录中的编译文件
clean:
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir clean; \
	done
	@echo "File cleanup completed."
	