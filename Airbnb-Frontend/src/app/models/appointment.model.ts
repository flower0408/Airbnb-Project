export interface Appointment {
    id:string;
    available: Date[];
    accommodationId?: string;
    pricePerGuest: number;
    pricePerAccommodation: number;
  }
  