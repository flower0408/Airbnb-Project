export interface Reservation {
    id?: string; 
    period: Date[];
    byUserId: string;
    accommodationId?: string;
    price: number;
  }
  