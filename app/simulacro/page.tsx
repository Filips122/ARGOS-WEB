import { SimulationConsole } from '@/components/SimulationConsole';

export const metadata = {
  title: 'ARGOS · Simulacro de bloqueo temprano',
  description: 'Cómo actuarían los modelos del TFM sobre alertas reales de Wazuh, sin ejecutar ninguna acción.',
};

export default function SimulacroPage() {
  return <SimulationConsole />;
}
