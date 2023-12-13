import {HttpClient, HttpHeaders, HttpParams} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Accommodation } from '../models/accommodation.model';
import { environment } from 'src/environments/environment';
import {catchError, Observable} from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AccommodationService {

  private url = "accommodations";
  constructor(private http: HttpClient) { }

  createAccommodation(accommodation: Accommodation): Observable<any> {

    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/`, accommodation);
  }

  getAllAccommodations(): Observable<any> {
    const url = `${environment.baseApiUrl}/${this.url}/`;
    return this.http.get(url);
  }

  getAccommodationById(accommodationId: string): Observable<Accommodation> {
    const url = `${environment.baseApiUrl}/${this.url}/${accommodationId}`;
    return this.http.get<Accommodation>(url);
  }

 /* searchAccommodations(location: string, minGuests: number): Observable<Accommodation[]> {
    const params = new HttpParams()
      .set('location', location)
      .set('minGuests', minGuests.toString())

    return this.http.get<Accommodation[]>(`${environment.baseApiUrl}/${this.url}/search`, { params });
  }*/
  searchAccommodations(
    location: string,
    minGuests: number,
    startDate: string,
    endDate: string
  ): Observable<Accommodation[]> {
    const params = new HttpParams()
      .set('location', location)
      .set('minGuests', minGuests.toString())
      .set('startDate', startDate)
      .set('endDate', endDate);

    return this.http.get<Accommodation[]>(`${environment.baseApiUrl}/${this.url}/search`, { params });
  }
}
