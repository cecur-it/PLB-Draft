interface SensorEpsSample {
  status: string;
  packetRate: number;
}

export function calculateSensorEps(sensors: readonly SensorEpsSample[] | null | undefined): number {
  if (!sensors?.length) return 0;
  return sensors.reduce((total, sensor) => total + (sensor.status !== 'OFFLINE' ? sensor.packetRate : 0), 0);
}
