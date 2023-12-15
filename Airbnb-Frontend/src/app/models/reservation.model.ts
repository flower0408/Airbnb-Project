import { Accommodation } from "./accommodation.model";

export interface Reservation {
    id?: string; 
    period: Date[];
    byUserId: string;
    accommodationId?: string;
    price: number;

    accommodation?: Accommodation;
  }
  