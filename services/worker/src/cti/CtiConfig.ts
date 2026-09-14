
import { ICtiProvider, IGeoProvider } from './providers/ICtiProvider';
import { NullCtiProvider, NullGeoProvider } from './providers/NullProvider';

export class CtiConfig {
  public static getCtiProvider(): ICtiProvider {
    // In future phases, we can check process.env.CTI_PROVIDER and return a real provider.
    // For Phase 14.1, we only implement the foundation (NullProvider).
    return new NullCtiProvider();
  }

  public static getGeoProvider(): IGeoProvider {
    return new NullGeoProvider();
  }
}
