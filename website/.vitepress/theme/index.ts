import DefaultTheme from 'vitepress/theme'
import ProductHome from './ProductHome.vue'
import InstallRequest from './InstallRequest.vue'
import EditorCards from './EditorCards.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ProductHome', ProductHome)
    app.component('InstallRequest', InstallRequest)
    app.component('EditorCards', EditorCards)
  }
}
