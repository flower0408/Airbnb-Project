import {HttpClient, HttpHeaders, HttpParams} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Accommodation } from '../models/accommodation.model';
import { environment } from 'src/environments/environment';
import {catchError, Observable} from 'rxjs';
import { Rate } from '../models/rate.model';

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

  getRatesByAccommodation(id: string): Observable<any> {
    const url = `${environment.baseApiUrl}/${this.url}/getRatesByAccommodation/${id}`;
    return this.http.get<any>(url);
  }

  getRatesByHost(id: any): Observable<any> {
    const url = `${environment.baseApiUrl}/${this.url}/getRatesByHost/${id}`;
    return this.http.get<any>(url);
  }

  createRateAccommodation(rate:any): Observable<any> {
    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/createRateForAccommodation`, rate);
  }

  createRateHost(rate:any): Observable<any> {
    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/createRateForHost`, rate);
  }

  updateRate(rateID:string,rate:any): Observable<any> {
    return this.http.patch<any>(`${environment.baseApiUrl}/${this.url}/updateRate/${rateID}`, rate);
  }

}
