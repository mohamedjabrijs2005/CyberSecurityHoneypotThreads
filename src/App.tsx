import React, { useState } from 'react';
import LoginDecoy from './components/LoginDecoy';
import Dashboard from './components/Dashboard';
import { Shield } from 'lucide-react';

function App() {
  const [currentView, setCurrentView] = useState<'decoy' | 'dashboard'>('decoy');

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Admin Toggle - Hidden in top corner */}
      <div className="fixed top-4 right-4 z-50">
        <button
          onClick={() => setCurrentView(currentView === 'decoy' ? 'dashboard' : 'decoy')}
          className="flex items-center gap-2 px-3 py-1 bg-gray-800 text-white rounded-lg text-sm hover:bg-gray-700 transition-colors"
        >
          <Shield className="w-4 h-4" />
          {currentView === 'decoy' ? 'Admin' : 'Decoy'}
        </button>
      </div>;

      {currentView === 'decoy' ? <LoginDecoy /> : <Dashboard />} ;
    </div>
  );
}

export default App;