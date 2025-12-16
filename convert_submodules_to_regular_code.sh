@ -0,0 +1,275 @@
#!/bin/bash
#
# 脚本名称: convert_submodules_to_regular_code.sh
# 功能: 将 Git submodules 转换为普通代码目录
# 作用: 解决构建环境无法拉取 submodule 的问题
# 使用方法: ./convert_submodules_to_regular_code.sh
#

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否在 git 仓库中
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "当前目录不是 Git 仓库！"
        exit 1
    fi
    log_success "检测到 Git 仓库"
}

# 备份 .gitmodules 文件
backup_gitmodules() {
    if [ -f .gitmodules ]; then
        cp .gitmodules .gitmodules.backup
        log_success "已备份 .gitmodules -> .gitmodules.backup"
    else
        log_warning "没有找到 .gitmodules 文件"
    fi
}

# 获取所有 submodule 路径
get_submodule_paths() {
    if [ -f .gitmodules ]; then
        git config --file .gitmodules --get-regexp path | awk '{ print $2 }'
    fi
}

# 递归删除所有 .git 文件和目录（除了根目录的 .git）
remove_nested_git() {
    local submodule_path=$1
    
    if [ -d "$submodule_path" ]; then
        log_info "处理 $submodule_path 中的 .git 文件/目录..."
        
        # 递归删除所有 .git 文件和目录
        find "$submodule_path" -name ".git" -exec rm -rf {} + 2>/dev/null || true
        
        # 删除所有嵌套的 .gitmodules
        find "$submodule_path" -name ".gitmodules" -exec rm -f {} + 2>/dev/null || true
        
        log_success "已清理 $submodule_path 中的 Git 元数据"
    fi
}

# 从 Git 索引中移除 submodule
remove_submodule_from_index() {
    local submodule_path=$1
    
    log_info "从 Git 索引移除 submodule: $submodule_path"
    git rm --cached "$submodule_path" 2>/dev/null || true
    
    # 检查是否还在索引中（160000 是 submodule 的模式）
    if git ls-files --stage | grep -q "^160000.*$submodule_path"; then
        log_warning "$submodule_path 仍在索引中，尝试强制移除..."
        git rm -f --cached "$submodule_path" 2>/dev/null || true
    fi
}

# 将目录作为普通代码添加到 Git
add_as_regular_code() {
    local submodule_path=$1
    
    if [ -d "$submodule_path" ]; then
        log_info "将 $submodule_path 添加为普通代码..."
        git add -f "$submodule_path/"
        
        # 验证是否成功添加
        local file_count=$(git ls-files "$submodule_path" | wc -l)
        if [ "$file_count" -gt 0 ]; then
            log_success "成功添加 $submodule_path ($file_count 个文件)"
        else
            log_error "添加 $submodule_path 失败！"
            return 1
        fi
    else
        log_warning "目录不存在: $submodule_path"
    fi
}

# 清理 .git/modules 目录
clean_git_modules() {
    if [ -d .git/modules ]; then
        log_info "清理 .git/modules 目录..."
        rm -rf .git/modules
        log_success "已删除 .git/modules"
    fi
}

# 清理 .git/config 中的 submodule 配置
clean_git_config() {
    log_info "清理 .git/config 中的 submodule 配置..."
    
    # 获取所有 submodule 配置段
    local submodule_sections=$(git config --local --get-regexp 'submodule\.' | awk -F'.' '{print $2}' | sort -u)
    
    for section in $submodule_sections; do
        if [ -n "$section" ]; then
            git config --local --remove-section "submodule.$section" 2>/dev/null || true
            log_success "已移除配置: submodule.$section"
        fi
    done
}

# 删除 .gitmodules 文件
remove_gitmodules() {
    if [ -f .gitmodules ]; then
        log_info "删除 .gitmodules 文件..."
        rm .gitmodules
        git rm --cached .gitmodules 2>/dev/null || true
        log_success "已删除 .gitmodules"
    fi
}

# 验证转换结果
verify_conversion() {
    log_info "验证转换结果..."
    
    # 检查是否还有 submodule 模式的文件
    local submodule_entries=$(git ls-files --stage | grep "^160000" | wc -l)
    
    if [ "$submodule_entries" -eq 0 ]; then
        log_success "✅ 没有 submodule 了！所有 submodule 已转换为普通代码"
        return 0
    else
        log_error "❌ 仍有 $submodule_entries 个 submodule 未转换"
        log_info "详细信息:"
        git ls-files --stage | grep "^160000"
        return 1
    fi
}

# 显示转换摘要
show_summary() {
    echo ""
    echo "=========================================="
    log_info "转换摘要"
    echo "=========================================="
    
    # 统计变更
    local deleted=$(git status --short | grep "^D " | wc -l)
    local added=$(git status --short | grep "^A " | wc -l)
    
    echo -e "${GREEN}删除的 submodule:${NC} $deleted"
    echo -e "${GREEN}添加的文件:${NC} $added"
    echo ""
    
    # 显示主要变更
    log_info "主要变更:"
    git status --short | head -20
    
    if [ "$(git status --short | wc -l)" -gt 20 ]; then
        echo "... (还有更多文件，使用 'git status' 查看完整列表)"
    fi
    
    echo ""
    echo "=========================================="
    log_success "转换完成！"
    echo "=========================================="
    echo ""
    echo "下一步操作:"
    echo "  1. 检查变更: git status"
    echo "  2. 查看差异: git diff --staged --stat"
    echo "  3. 提交变更: git commit -m 'Convert submodules to regular code'"
    echo "  4. 推送代码: git push"
    echo ""
}

# 主函数
main() {
    echo ""
    echo "=========================================="
    echo "  Submodule 转换工具"
    echo "  将 Git Submodules 转换为普通代码"
    echo "=========================================="
    echo ""
    
    # 1. 检查环境
    check_git_repo
    
    # 2. 备份
    backup_gitmodules
    
    # 3. 获取 submodule 列表
    log_info "获取 submodule 列表..."
    local submodules=($(get_submodule_paths))
    
    if [ ${#submodules[@]} -eq 0 ]; then
        log_warning "没有找到 submodule，可能已经转换过了"
        
        # 检查是否有遗留的 160000 模式文件
        if git ls-files --stage | grep -q "^160000"; then
            log_info "发现遗留的 submodule 引用，尝试清理..."
            submodules=($(git ls-files --stage | grep "^160000" | awk '{print $4}'))
        else
            log_success "当前仓库没有 submodule"
            exit 0
        fi
    fi
    
    log_success "找到 ${#submodules[@]} 个 submodule: ${submodules[*]}"
    echo ""
    
    # 4. 处理每个 submodule
    for submodule in "${submodules[@]}"; do
        echo "----------------------------------------"
        log_info "处理 submodule: $submodule"
        echo "----------------------------------------"
        
        # 4.1 从索引移除
        remove_submodule_from_index "$submodule"
        
        # 4.2 清理嵌套的 .git
        remove_nested_git "$submodule"
        
        # 4.3 添加为普通代码
        add_as_regular_code "$submodule"
        
        echo ""
    done
    
    # 5. 清理全局配置
    echo "----------------------------------------"
    log_info "清理全局配置"
    echo "----------------------------------------"
    clean_git_modules
    clean_git_config
    remove_gitmodules
    echo ""
    
    # 6. 验证
    echo "----------------------------------------"
    verify_conversion
    echo "----------------------------------------"
    echo ""
    
    # 7. 显示摘要
    show_summary
}

# 运行主函数
main "$@"

