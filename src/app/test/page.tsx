"use client"
import React, { useEffect, useState } from 'react';
import {
  allSysInfo,
  memoryInfo,
  staticInfo,
  cpuInfo,
  batteries
} from 'tauri-plugin-system-info-api';

const Dashboard = () => {
  const [sysInfo, setSysInfo] = useState(null);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    // Ensure this code only runs on the client-side
    if (typeof window !== 'undefined' && window.__TAURI__) {
      (async () => {
        try {
          // Fetch system information
          const systemInfo = await allSysInfo();
          const memory = await memoryInfo();
          const staticData = await staticInfo();
          const cpu = await cpuInfo();
          const batts = await batteries();

          console.log('System Info:', systemInfo);
          console.log('Memory Info:', memory);
          console.log('Static Info:', staticData);
          console.log('CPU Info:', cpu);
          console.log('Batteries Info:', batts);

          setSysInfo({
            systemInfo,
            memory,
            staticData,
            cpu,
            batts
          });
        } catch (err) {
          console.error('Error invoking Tauri APIs:', err);
          setError(err);
        }
      })();
    } else {
      console.error('Tauri environment is not available');
    }
  }, []);

  return (
    <div>
      {/* Render your component UI */}
      {error && <p>Error: {error.message}</p>}
      {sysInfo && (
        <div>
          <pre>{JSON.stringify(sysInfo, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
