// client/src/App.jsx

// React removed
import { Outlet } from 'react-router-dom';
import { Toaster } from 'react-hot-toast'; // 🎨 Modern Toast Bildirimleri

// Bu bileşen, /admin veya /mervan gibi
// tüm sayfalar için genel bir "kabuk" görevi görür.
// <Outlet /> ise, o anki URL'ye karşılık gelen
// (Customer.jsx, Admin.jsx vb.) bileşenin render edileceği yerdir.

function App() {
  return (
    <>
      <Toaster
        position="top-center"
        toastOptions={{
          duration: 4000,
          style: {
            background: 'var(--paper)',
            color: 'var(--text)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius)',
            boxShadow: 'var(--shadow)',
            padding: '16px 20px',
            fontSize: '14px',
            fontWeight: '500',
            maxWidth: '500px',
          },
          success: {
            iconTheme: {
              primary: 'var(--ok)',
              secondary: 'var(--paper)',
            },
            style: {
              borderLeft: '4px solid var(--ok)',
            },
          },
          error: {
            iconTheme: {
              primary: 'var(--danger)',
              secondary: 'var(--paper)',
            },
            style: {
              borderLeft: '4px solid var(--danger)',
            },
            duration: 5000,
          },
        }}
      />
      {/* Gelecekte buraya tüm sayfalarda ortak bir 
        Header veya Footer koyabilirsiniz.
        Şimdilik boş bırakıyoruz.
      */}
      <Outlet />
    </>
  );
}

export default App;