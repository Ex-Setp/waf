<template>
  <section class="page-stack">
    <div class="sl-card ia-placeholder">
      <div class="sl-card-head">
        <span class="sl-card-title">访问统计</span>
        <el-tag type="info" effect="light">已迁移入口</el-tag>
      </div>
      <div class="ia-placeholder__body">
        <p>访问统计已并入“防护配置 / 访问统计 / 攻击日志解释”。此页不再展示硬编码 Top Path、访问量或 QPS。</p>
        <p class="ia-placeholder__note">真实统计必须来自 access_logs、attack_logs 或 reports 聚合；API 失败时应显示错误态，不能回退样例数据。</p>
        <div class="ia-placeholder__chips">
          <router-link class="ia-placeholder__chip" to="/protection-config">进入防护配置</router-link>
        </div>
      </div>
    </div>
  </section>
</template>
