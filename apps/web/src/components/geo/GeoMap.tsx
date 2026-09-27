import { useEffect, useMemo, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Circle, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Crosshair, MapPin, Radio } from 'lucide-react';
import type { ValidatedGeoItem } from './geoUtils';
import { formatCoordinates, formatAccuracyRadius } from './geoUtils';

// Fix default Leaflet icon paths in bundlers (Vite)
delete (L.Icon.Default.prototype as unknown as { _getIconUrl?: unknown })._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

/**
 * Creates high-fidelity vector DivIcons for markers.
 * Immune to broken asset paths, razor-sharp on retina, with dynamic pulse styling.
 */
function createMarkerIcon(isSelected: boolean) {
  const outerColor = isSelected ? '#38bdf8' : '#f43f5e';
  const innerGradient = isSelected
    ? 'linear-gradient(135deg, #0284c7, #38bdf8)'
    : 'linear-gradient(135deg, #e11d48, #fb7185)';
  const glow = isSelected ? 'rgba(56, 189, 248, 0.9)' : 'rgba(244, 63, 94, 0.7)';

  return L.divIcon({
    className: 'cipherscope-map-marker',
    html: `
      <div style="position: relative; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;">
        <span style="position: absolute; width: 100%; height: 100%; border-radius: 9999px; background-color: ${outerColor}; opacity: 0.35; animation: ping 2s cubic-bezier(0, 0, 0.2, 1) infinite;"></span>
        <div style="position: relative; width: 16px; height: 16px; border-radius: 9999px; background: ${innerGradient}; border: 2px solid #ffffff; box-shadow: 0 0 10px ${glow}; display: flex; align-items: center; justify-content: center;">
          <div style="width: 4px; height: 4px; border-radius: 9999px; background: #ffffff;"></div>
        </div>
      </div>
    `,
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -14],
  });
}

/**
 * Map controller hook that handles:
 * 1. Automatic container resize invalidation (tab change, card resize).
 * 2. Automatic initial centering (bounds fit for multiple, fixed zoom for single).
 * 3. Pan-and-zoom flyTo when an item is selected.
 */
function MapController({
  items,
  selectedItem,
}: {
  items: ValidatedGeoItem[];
  selectedItem: ValidatedGeoItem | null;
}) {
  const map = useMap();
  const hasInitializedRef = useRef(false);

  // Invalidate size on mount and on window resize
  useEffect(() => {
    map.invalidateSize();
    const handleResize = () => map.invalidateSize();
    window.addEventListener('resize', handleResize);
    const timer = setTimeout(() => map.invalidateSize(), 300);
    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(timer);
    };
  }, [map]);

  // Selected item flyTo
  useEffect(() => {
    if (selectedItem) {
      map.flyTo([selectedItem.latitude, selectedItem.longitude], Math.max(map.getZoom(), 6), {
        duration: 0.8,
      });
      return;
    }

    // Auto-fit on initial items load if not yet initialized
    if (!hasInitializedRef.current && items.length > 0) {
      if (items.length === 1) {
        map.setView([items[0].latitude, items[0].longitude], 6);
      } else {
        const bounds = L.latLngBounds(items.map((i) => [i.latitude, i.longitude]));
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
      }
      hasInitializedRef.current = true;
    }
  }, [map, selectedItem, items]);

  return null;
}

interface GeoMapProps {
  items: ValidatedGeoItem[];
  selectedIp: string | null;
  onSelectIp: (ip: string) => void;
  className?: string;
}

export const GeoMap = ({ items, selectedIp, onSelectIp, className = '' }: GeoMapProps) => {
  const selectedItem = useMemo(
    () => items.find((i) => i.ip === selectedIp) ?? null,
    [items, selectedIp]
  );

  // Fallback center: center on selected, first item, or geographic center of US/World
  const defaultCenter = useMemo<[number, number]>(() => {
    if (selectedItem) return [selectedItem.latitude, selectedItem.longitude];
    if (items.length > 0) return [items[0].latitude, items[0].longitude];
    return [20, 0];
  }, [items, selectedItem]);

  const defaultZoom = items.length === 1 ? 5 : 3;

  return (
    <div className={`relative w-full h-[520px] rounded-xl overflow-hidden border border-slate-800 bg-slate-950 ${className}`}>
      <MapContainer
        center={defaultCenter}
        zoom={defaultZoom}
        minZoom={2}
        maxZoom={18}
        scrollWheelZoom={true}
        className="w-full h-full z-0 cipherscope-leaflet-container"
      >
        {/* OpenStreetMap Real Tile Layer */}
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          maxZoom={19}
        />

        <MapController items={items} selectedItem={selectedItem} />

        {/* Render Accuracy Circles for all located IPs */}
        {items.map((item) => {
          if (!item.accuracyRadiusMeters) return null;
          const isSelected = item.ip === selectedIp;
          return (
            <Circle
              key={`circle-${item.ip}`}
              center={[item.latitude, item.longitude]}
              radius={item.accuracyRadiusMeters}
              pathOptions={{
                color: isSelected ? '#38bdf8' : '#f43f5e',
                fillColor: isSelected ? '#38bdf8' : '#f43f5e',
                fillOpacity: isSelected ? 0.16 : 0.08,
                weight: isSelected ? 1.5 : 1,
                dashArray: '4 4',
              }}
            />
          );
        })}

        {/* Render Markers for all public located IPs */}
        {items.map((item) => {
          const isSelected = item.ip === selectedIp;
          const icon = createMarkerIcon(isSelected);

          return (
            <Marker
              key={`marker-${item.ip}`}
              position={[item.latitude, item.longitude]}
              icon={icon}
              eventHandlers={{
                click: () => onSelectIp(item.ip),
              }}
            >
              <Popup className="cipherscope-popup" autoPan={true}>
                <div className="p-1 space-y-2 min-w-[220px] text-slate-100">
                  <div className="flex items-center justify-between border-b border-slate-700/60 pb-1.5">
                    <span className="font-mono text-sm font-semibold text-sky-400">{item.ip}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {item.classification}
                    </span>
                  </div>

                  <div className="text-xs space-y-1">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Location:</span>
                      <span className="font-medium text-slate-200">
                        {[item.city, item.region, item.country].filter(Boolean).join(', ') || 'Unknown'}
                      </span>
                    </div>

                    {item.isp && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">ISP / Org:</span>
                        <span className="text-slate-200 truncate max-w-[130px]" title={item.isp}>
                          {item.isp}
                        </span>
                      </div>
                    )}

                    {item.asn && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">ASN:</span>
                        <span className="text-slate-200 font-mono">{item.asn}</span>
                      </div>
                    )}

                    <div className="flex justify-between">
                      <span className="text-slate-400">Coordinates:</span>
                      <span className="text-slate-300 font-mono text-[11px]">
                        {formatCoordinates(item.latitude, item.longitude)}
                      </span>
                    </div>

                    <div className="flex justify-between">
                      <span className="text-slate-400">Accuracy:</span>
                      <span className="text-slate-300 text-[11px]">
                        {formatAccuracyRadius(item.accuracyRadiusKm)}
                      </span>
                    </div>

                    <div className="flex justify-between pt-1 border-t border-slate-700/40 text-[10px] text-slate-400">
                      <span>Provider: <strong className="text-emerald-400">{item.provider}</strong></span>
                      <span className="italic">Approximate location</span>
                    </div>
                  </div>
                </div>
              </Popup>
            </Marker>
          );
        })}
      </MapContainer>

      {/* Map Legend Overlay */}
      <div className="absolute top-3 right-3 z-[1000] bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-lg p-2.5 shadow-xl text-xs space-y-1.5 pointer-events-auto">
        <div className="flex items-center gap-2 text-slate-300 font-medium">
          <Crosshair className="w-3.5 h-3.5 text-blue-400" />
          <span>Interactive Geo Map</span>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-400">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span>
          <span>Public Relay IP ({items.length})</span>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-400">
          <span className="w-2.5 h-2.5 rounded-full bg-sky-400 inline-block"></span>
          <span>Selected Target</span>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400 border-t border-slate-800 pt-1">
          <Radio className="w-3 h-3 text-cyan-400 shrink-0" />
          <span>Dashed circle = MaxMind Accuracy Radius</span>
        </div>
      </div>

      {/* Empty State Banner if no items have coordinates */}
      {items.length === 0 && (
        <div className="absolute inset-0 z-[1001] bg-slate-950/80 backdrop-blur-sm flex flex-col items-center justify-center text-center p-6 gap-3">
          <MapPin className="w-10 h-10 text-slate-600 animate-pulse" />
          <h4 className="text-base font-medium text-slate-200">No Geolocation Coordinates Available</h4>
          <p className="text-xs text-slate-400 max-w-md">
            No public relay IPs with enriched MaxMind coordinates have been observed yet. Private, loopback, and local network IPs are excluded from geographic mapping.
          </p>
        </div>
      )}
    </div>
  );
};
