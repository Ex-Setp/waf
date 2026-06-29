<template>
  <section class="page-stack">
    <div class="sl-card ia-placeholder">
      <div class="sl-card-head">
        <span class="sl-card-title">规则管理</span>
        <el-tag type="info" effect="light">已迁移入口</el-tag>
      </div>
      <div class="ia-placeholder__body">
        <p>规则管理已并入“防护配置 / 规则管理 / CRS”。此页不再展示硬编码规则集数量，避免把 OWASP CRS、语义规则等伪数据误标为完成态。</p>
        <p class="ia-placeholder__note">请通过左侧“防护配置”进入真实 API 驱动的规则集、规则列表、规则组、CRS 状态和 rule exclusion 承接页面。</p>
        <div class="ia-placeholder__chips">
          <router-link class="ia-placeholder__chip" to="/protection-config">进入防护配置</router-link>
        </div>
      </div>
    </div>
  </section>
</template>
