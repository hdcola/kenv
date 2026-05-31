import { createApp } from "vue";
import App from "./App.vue";
import { createKenvI18n } from "./i18n";

createApp(App).use(createKenvI18n()).mount("#app");
