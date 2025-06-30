# Bitrix_finder
Script to find Bitrix CMS in domain list

🚨 **Bitrix_finder** — асинхронный сканер для массовой проверки веб-серверов на наличие CMS Bitrix.  
Поддерживает быструю проверку большого числа доменов, определяет признаки Bitrix, обрабатывает перенаправления и сохраняет результаты в CSV.

---

## 💡 Возможности

✅ Массовая проверка списка доменов (через файл или аргумент командной строки)  
✅ Проверка по основным признакам Bitrix:
- Наличие директорий `/bitrix/`, `/bitrix/admin/`
- Упоминания `bitrix` в HTML
- Cookie `BITRIX_SM`
- Заголовки `X-Powered-CMS`, `X-Powered-By`
✅ Выявление перенаправлений (и исключение "ложных" срабатываний)  
✅ Асинхронная (быстрая) обработка  
✅ Сохранение результатов в CSV

---

## ⚙️ Установка

```bash
git clone https://github.com/yourusername/bitrix-scanner.git
cd bitrix-scanner
pip install -r requirements.txt
