import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Reservation } from '../models/reservation.model';
import { Observable } from 'rxjs';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ReservationService {

  private url = "reservations";
  constructor(private http: HttpClient) { }

  createReservation(reservation: Reservation): Observable<any> {

    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/reservations`, reservation);
  }

}
