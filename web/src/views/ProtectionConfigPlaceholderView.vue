<script setup lang="ts">
const pendingItems = ['规则管理', '语义指纹', '访问统计']
</script>

<template>
  <section class="page-stack">
    <div class="sl-card ia-placeholder">
      <div class="sl-card-head">
        <span class="sl-card-title">防护配置</span>
        <el-tag type="warning" effect="light">规划中</el-tag>
      </div>
      <div class="ia-placeholder__body">
        <p>当前仅完成信息架构重组。本页将用于承接后续防护配置能力，详细交互和数据面板尚未实现。</p>
        <p class="ia-placeholder__note">以下子项将在后续任务补齐，当前不展示任何伪造运行数据：</p>
        <div class="ia-placeholder__chips">
          <span v-for="item in pendingItems" :key="item" class="ia-placeholder__chip">{{ item }}</span>
        </div>
      </div>
    </div>
  </section>
</template>
