import { Location } from "./location.model";

export interface Accommodation {
    id?: string;
    name: string;
    description?: string;
    images: string;
    location: Location;
    benefits: string;
    minGuest: number;
    maxGuest: number;
    ownerId: string;
}