import DefaultTheme from 'vitepress/theme'
import ProductHome from './ProductHome.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ProductHome', ProductHome)
  }
}
