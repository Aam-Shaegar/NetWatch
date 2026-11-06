import {createRoot} from 'react-dom/client';
import './style.css';
function App(){return <main><p className="label">NETWATCH / FOUNDATION</p><h1>Наблюдать. Понимать.<br/>Обнаруживать.</h1><p>Система анализа сетевого трафика</p><section><h2>Основа проекта подготовлена</h2><p>Go-сенсор → признаки → ML-сервис → инциденты</p><p className="status">Сбор трафика и модель ещё не подключены</p><p>Эта страница проверяет сборку интерфейса. Рабочие метрики появятся после реализации конвейера.</p></section></main>}
createRoot(document.getElementById('root')!).render(<App/>);
