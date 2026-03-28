import React, { useState, useEffect, useRef } from 'react';
import './IPTrackingMap.css';

// Simple map component using SVG world map
const IPTrackingMap = ({ locations = [], stats = {} }) => {
  const [selectedLocation, setSelectedLocation] = useState(null);
  const mapRef = useRef(null);

  // World map coordinates (simplified)
  const worldMap = {
    viewBox: "0 0 1000 500",
    countries: [
      { name: "Indonesia", code: "ID", x: 500, y: 250, lat: -0.7893, lon: 113.9213 },
      { name: "United States", code: "US", x: 200, y: 200, lat: 37.0902, lon: -95.7129 },
      { name: "China", code: "CN", x: 550, y: 200, lat: 35.8617, lon: 104.1954 },
      { name: "Russia", code: "RU", x: 550, y: 100, lat: 61.5240, lon: 105.3188 },
      { name: "India", code: "IN", x: 500, y: 220, lat: 20.5937, lon: 78.9629 },
      { name: "Brazil", code: "BR", x: 300, y: 300, lat: -14.2350, lon: -51.9253 },
      { name: "Germany", code: "DE", x: 450, y: 150, lat: 51.1657, lon: 10.4515 },
      { name: "United Kingdom", code: "GB", x: 430, y: 140, lat: 55.3781, lon: -3.4360 },
      { name: "Japan", code: "JP", x: 600, y: 200, lat: 36.2048, lon: 138.2529 },
      { name: "South Korea", code: "KR", x: 580, y: 200, lat: 35.9078, lon: 127.7669 },
    ]
  };

  // Group locations by country (REAL DATA ONLY)
  const locationsByCountry = locations.reduce((acc, loc) => {
    if (!loc) return acc; // Skip null locations
    
    const code = loc.country_code || loc.countryCode || "UNKNOWN";
    // Skip fake "Unknown" or "XX" countries (except localhost)
    if (code === "XX" && loc.ip !== "127.0.0.1" && loc.ip !== "::1" && loc.IP !== "127.0.0.1" && loc.IP !== "::1") {
      return acc; // Skip fake data
    }
    
    if (!acc[code]) {
      acc[code] = [];
    }
    acc[code].push(loc);
    return acc;
  }, {});
  
  // Debug: Log REAL locations
  useEffect(() => {
    if (locations.length > 0) {
      console.log('📍 REAL IP Locations received:', locations.length);
      locations.forEach((loc, idx) => {
        if (loc) {
          const ip = loc.ip || loc.IP || 'unknown';
          const city = loc.city || loc.City || 'unknown';
          const country = loc.country || loc.Country || 'unknown';
          const lat = loc.latitude || loc.lat || 0;
          const lon = loc.longitude || loc.lon || 0;
          console.log(`  [${idx + 1}] ${ip}: ${city}, ${country} (Lat: ${lat}, Lon: ${lon})`);
        }
      });
    } else {
      console.log('⚠️ No REAL IP locations data yet. Make some requests to populate the map.');
    }
  }, [locations]);

  // Get country data with attack counts
  const countryData = worldMap.countries.map(country => {
    const countryLocations = locationsByCountry[country.code] || [];
    const attackCount = countryLocations.reduce((sum, loc) => sum + (loc.attack_count || loc.attackCount || 0), 0);
    const ipCount = countryLocations.length;
    
    return {
      ...country,
      attackCount,
      ipCount,
      locations: countryLocations,
    };
  });

  // Calculate marker size based on attack count
  const getMarkerSize = (attackCount) => {
    if (attackCount === 0) return 5;
    if (attackCount < 5) return 10;
    if (attackCount < 20) return 15;
    if (attackCount < 50) return 20;
    return 25;
  };

  // Get marker color based on threat level
  const getMarkerColor = (attackCount, threatScore) => {
    if (attackCount === 0) return "#4CAF50"; // Green
    const score = threatScore || 0;
    if (score > 0.7) return "#F44336"; // Red
    if (score > 0.4) return "#FF9800"; // Orange
    return "#FFC107"; // Yellow
  };

  const handleMarkerClick = (country) => {
    setSelectedLocation(country);
  };

  return (
    <div className="ip-tracking-map-container">
      <div className="map-header">
        <h3>🌍 Global IP Attack Tracking (REAL DATA ONLY)</h3>
        <div className="map-stats">
          <span>Total IPs: {locations.length}</span>
          <span>Countries: {stats.unique_countries || Object.keys(locationsByCountry).length}</span>
          <span>Total Attacks: {stats.total_attacks || locations.reduce((sum, loc) => sum + (loc.attack_count || loc.attackCount || 0), 0)}</span>
          {locations.length === 0 && (
            <span style={{color: '#FF9800', display: 'block', marginTop: '10px'}}>
              ⚠️ No REAL IP data yet. Make requests from external IPs to populate the map.
              <br/>
              <small style={{fontSize: '11px', display: 'block', marginTop: '5px'}}>
                Note: Localhost (127.0.0.1) will not appear. Test with external IPs or wait for real traffic.
              </small>
            </span>
          )}
        </div>
      </div>

      <div className="map-wrapper">
        <svg
          ref={mapRef}
          viewBox={worldMap.viewBox}
          className="world-map"
          preserveAspectRatio="xMidYMid meet"
        >
          {/* World map background */}
          <rect width="1000" height="500" fill="#1e1e2e" />
          
          {/* Country markers */}
          {countryData.map((country) => {
            const markerSize = getMarkerSize(country.attackCount);
            const markerColor = getMarkerColor(
              country.attackCount,
              country.locations[0]?.threat_score || country.locations[0]?.threatScore || 0
            );
            
            return (
              <g key={country.code}>
                {/* Marker circle */}
                <circle
                  cx={country.x}
                  cy={country.y}
                  r={markerSize}
                  fill={markerColor}
                  stroke="#fff"
                  strokeWidth="2"
                  opacity={country.attackCount > 0 ? 0.8 : 0.4}
                  className="map-marker"
                  onClick={() => handleMarkerClick(country)}
                  style={{ cursor: 'pointer' }}
                />
                
                {/* Pulse animation for active attacks */}
                {country.attackCount > 0 && (
                  <circle
                    cx={country.x}
                    cy={country.y}
                    r={markerSize}
                    fill={markerColor}
                    opacity="0.3"
                    className="pulse-animation"
                  />
                )}
                
                {/* Country label */}
                {country.attackCount > 0 && (
                  <text
                    x={country.x}
                    y={country.y - markerSize - 5}
                    fill="#fff"
                    fontSize="12"
                    textAnchor="middle"
                    className="country-label"
                  >
                    {country.code}
                  </text>
                )}
              </g>
            );
          })}

          {/* Attack markers (if we have lat/lon) */}
          {locations
            .filter(loc => {
              const attackCount = loc.attack_count || loc.attackCount || 0;
              const lat = loc.latitude || loc.lat;
              const lon = loc.longitude || loc.lon;
              return attackCount > 0 && lat && lon;
            })
            .map((loc, index) => {
              const lat = loc.latitude || loc.lat || 0;
              const lon = loc.longitude || loc.lon || 0;
              // Convert lat/lon to SVG coordinates (simplified)
              const x = ((lon + 180) / 360) * 1000;
              const y = ((90 - lat) / 180) * 500;
              
              return (
                <g key={`attack-${index}`}>
                  <circle
                    cx={x}
                    cy={y}
                    r="4"
                    fill="#F44336"
                    opacity="0.8"
                    stroke="#fff"
                    strokeWidth="1"
                  />
                </g>
              );
            })}
        </svg>
      </div>

      {/* Location details panel */}
      {selectedLocation && (
        <div className="location-details-panel">
          <div className="panel-header">
            <h4>{selectedLocation.name}</h4>
            <button onClick={() => setSelectedLocation(null)}>×</button>
          </div>
          <div className="panel-content">
            <div className="detail-row">
              <span className="label">Country Code:</span>
              <span className="value">{selectedLocation.code}</span>
            </div>
            <div className="detail-row">
              <span className="label">Attack Count:</span>
              <span className="value critical">{selectedLocation.attackCount}</span>
            </div>
            <div className="detail-row">
              <span className="label">IP Addresses:</span>
              <span className="value">{selectedLocation.ipCount}</span>
            </div>
            {selectedLocation.locations.length > 0 && (
              <div className="ip-list">
                <h5>IP Addresses:</h5>
                {selectedLocation.locations.slice(0, 10).map((loc, idx) => (
                  <div key={idx} className="ip-item">
                    <span className="ip-address">{loc.ip || loc.IP}</span>
                    <span className="ip-attacks">{(loc.attack_count || loc.attackCount || 0)} attacks</span>
                    {(loc.city || loc.City) && <span className="ip-city">{loc.city || loc.City}</span>}
                  </div>
                ))}
                {selectedLocation.locations.length > 10 && (
                  <div className="more-ips">+{selectedLocation.locations.length - 10} more</div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="map-legend">
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: "#F44336" }}></div>
          <span>High Threat (&gt;70%)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: "#FF9800" }}></div>
          <span>Medium Threat (40-70%)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: "#FFC107" }}></div>
          <span>Low Threat (&lt;40%)</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ backgroundColor: "#4CAF50" }}></div>
          <span>No Attacks</span>
        </div>
      </div>
    </div>
  );
};

export default IPTrackingMap;

