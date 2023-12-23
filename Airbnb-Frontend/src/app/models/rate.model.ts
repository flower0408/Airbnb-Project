import { User } from "./user.model"

export interface Rate {
    id:                 string
	byGuestId:          string             
	forHostId:          string             
	forAccommodationId: string           
	createdAt:          string         
	updatedAt:          string             
	rate:               number     
	user: User         
}